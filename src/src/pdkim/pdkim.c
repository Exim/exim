/* $Cambridge: exim/src/src/pdkim/pdkim.c,v 1.1.2.6 2009/03/17 12:57:37 tom Exp $ */
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
  "dns/txt",
  NULL
};
char *pdkim_algos[] = {
  "rsa-sha256",
  "rsa-sha1",
  NULL
};
char *pdkim_canons[] = {
  "simple",
  "relaxed",
  NULL
};
char *pdkim_hashes[] = {
  "sha256",
  "sha1",
  NULL
};
char *pdkim_keytypes[] = {
  "rsa",
  NULL
};

typedef struct pdkim_combined_canon_entry {
  char *str;
  int canon_headers;
  int canon_body;
} pdkim_combined_canon_entry;
pdkim_combined_canon_entry pdkim_combined_canons[] = {
  { "simple/simple",    PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { "simple/relaxed",   PDKIM_CANON_SIMPLE,   PDKIM_CANON_RELAXED },
  { "relaxed/simple",   PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { "relaxed/relaxed",  PDKIM_CANON_RELAXED,  PDKIM_CANON_RELAXED },
  { "simple",           PDKIM_CANON_SIMPLE,   PDKIM_CANON_SIMPLE },
  { "relaxed",          PDKIM_CANON_RELAXED,  PDKIM_CANON_SIMPLE },
  { NULL,               0,                    0 }
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
void pdkim_hexprint(FILE *stream, char *data, int len, int lf) {
  int i;
  unsigned char *p = (unsigned char *)data;

  for (i=0;i<len;i++) {
    int c = p[i];
    fprintf(stream,"%02x ",c);
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
char *pdkim_strtrim(pdkim_str *str) {
  char *p = str->str;
  char *q = str->str;
  while ( (*p != '\0') && ((*p == '\t') || (*p == ' ')) ) p++;
  while (*p != '\0') {*q = *p; q++; p++;};
  *q = '\0';
  while ( (q != str->str) && ( (*q == '\0') || (*q == '\t') || (*q == ' ') ) ) {
    *q = '\0';
    q--;
  }
  str->len = strlen(str->str);
  return str->str;
};
char *pdkim_strclear(pdkim_str *str) {
  str->str[0] = '\0';
  str->len = 0;
  return str->str;
};
void pdkim_strfree(pdkim_str *str) {
  if (str == NULL) return;
  if (str->str != NULL) free(str->str);
  free(str);
};


/* -------------------------------------------------------------------------- */
/* Matches the name of the passed raw "header" against
   the passed colon-separated "list", starting at entry
   "start". Returns the position of the header name in
   the list. */
int header_name_match(char *header,
                      char *list,
                      int   start) {
  char *hname;
  char *lcopy;
  char *p;
  char *q;
  int pos = 0;
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
    if (pos >= start) {
      if (strcasecmp(p,hname) == 0) {
        rc = pos;
        goto BAIL;
      }
    }
    p = q+1;
    q = strchr(p,':');
    pos++;
  }
  if (pos >= start) {
    if (strcasecmp(p,hname) == 0)
      rc = pos;
  }
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
#define PDKIM_QP_ERROR_DECODE -1
char *pdkim_decode_qp_char(char *qp_p, int *c) {
  char *initial_pos = qp_p;

  /* Advance one char */
  qp_p++;

  /* Check for two hex digits and decode them */
  if (isxdigit(*qp_p) && isxdigit(qp_p[1])) {
    /* Do hex conversion */
    if (isdigit(*qp_p)) {*c = *qp_p - '0';}
    else {*c = toupper(*qp_p) - 'A' + 10;};
    *c <<= 4;
    if (isdigit(qp_p[1])) {*c |= qp_p[1] - '0';}
    else {*c |= toupper(qp_p[1]) - 'A' + 10;};
    return qp_p + 2;
  };

  /* Illegal char here */
  *c = PDKIM_QP_ERROR_DECODE;
  return initial_pos;
}


/* -------------------------------------------------------------------------- */
char *pdkim_decode_qp(char *str) {
  int nchar = 0;
  char *q;
  char *p = str;
  char *n = malloc(strlen(p)+1);
  if (n == NULL) return NULL;
  *n = '\0';
  q = n;
  while (*p != '\0') {
    if (*p == '=') {
      p = pdkim_decode_qp_char(p,&nchar);
      if (nchar >= 0) {
        *q = nchar;
        q++;
        continue;
      }
    }
    else {
      *q = *p;
      q++;
    }
    p++;
  }
  return n;
}


/* -------------------------------------------------------------------------- */
char *pdkim_decode_base64(char *str, int *num_decoded) {
  int dlen = 0;
  char *res;

  base64_decode(NULL, &dlen, (unsigned char *)str, strlen(str));
  res = malloc(dlen+1);
  if (res == NULL) return NULL;
  if (base64_decode((unsigned char *)res,&dlen,(unsigned char *)str,strlen(str)) != 0) {
    free(res);
    return NULL;
  }
  if (num_decoded != NULL) *num_decoded = dlen;
  return res;
}

/* -------------------------------------------------------------------------- */
char *pdkim_encode_base64(char *str, int num) {
  int dlen = 0;
  char *res;

  base64_encode(NULL, &dlen, (unsigned char *)str, num);
  res = malloc(dlen+1);
  if (res == NULL) return NULL;
  if (base64_encode((unsigned char *)res,&dlen,(unsigned char *)str,num) != 0) {
    free(res);
    return NULL;
  }
  return res;
}


/* -------------------------------------------------------------------------- */
#define PDKIM_HDR_LIMBO 0
#define PDKIM_HDR_TAG   1
#define PDKIM_HDR_VALUE 2
pdkim_signature *pdkim_parse_sig_header(pdkim_ctx *ctx, char *raw_hdr) {
  pdkim_signature *sig ;
  char *p,*q;
  pdkim_str *cur_tag = NULL;
  pdkim_str *cur_val = NULL;
  int past_hname = 0;
  int in_b_val = 0;
  int where = PDKIM_HDR_LIMBO;
  int i;

  sig = malloc(sizeof(pdkim_signature));
  if (sig == NULL) return NULL;
  memset(sig,0,sizeof(pdkim_signature));

  sig->rawsig_no_b_val = malloc(strlen(raw_hdr)+1);
  if (sig->rawsig_no_b_val == NULL) {
    free(sig);
    return NULL;
  }

  p = raw_hdr;
  q = sig->rawsig_no_b_val;

  while (*p != '\0') {

    /* Ignore FWS */
    if ( (*p == '\r') || (*p == '\n') )
      goto NEXT_CHAR;

    /* Fast-forward through header name */
    if (!past_hname) {
      if (*p == ':') past_hname = 1;
      goto NEXT_CHAR;
    }

    if (where == PDKIM_HDR_LIMBO) {
      /* In limbo, just wait for a tag-char to appear */
      if (!((*p >= 'a') && (*p <= 'z')))
        goto NEXT_CHAR;

      where = PDKIM_HDR_TAG;
    }

    if (where == PDKIM_HDR_TAG) {
      if (cur_tag == NULL)
        cur_tag = pdkim_strnew(NULL);

      if ((*p >= 'a') && (*p <= 'z'))
        pdkim_strncat(cur_tag,p,1);

      if (*p == '=') {
        if (strcmp(cur_tag->str,"b") == 0) {
          *q = '='; q++;
          in_b_val = 1;
        }
        where = PDKIM_HDR_VALUE;
        goto NEXT_CHAR;
      }
    }

    if (where == PDKIM_HDR_VALUE) {
      if (cur_val == NULL)
        cur_val = pdkim_strnew(NULL);

      if ( (*p == '\r') || (*p == '\n') )
        goto NEXT_CHAR;

      if (*p == ';') {
        if (cur_tag->len > 0) {
          pdkim_strtrim(cur_val);
          #ifdef PDKIM_DEBUG
          if (ctx->debug_stream)
            fprintf(ctx->debug_stream, "%s=%s\n", cur_tag->str, cur_val->str);
          #endif
          switch (cur_tag->str[0]) {
            case 'b':
              switch (cur_tag->str[1]) {
                case 'h':
                  sig->bodyhash = pdkim_decode_base64(cur_val->str,&(sig->bodyhash_len));
                break;
                default:
                  sig->sigdata = pdkim_decode_base64(cur_val->str,&(sig->sigdata_len));
                break;
              }
            break;
            case 'v':
              if (strcmp(cur_val->str,PDKIM_SIGNATURE_VERSION) == 0) {
                /* We only support version 1, and that is currently the
                   only version there is. */
                sig->version = 1;
              }
            break;
            case 'a':
              i = 0;
              while (pdkim_algos[i] != NULL) {
                if (strcmp(cur_val->str,pdkim_algos[i]) == 0 ) {
                  sig->algo = i;
                  break;
                }
                i++;
              }
            break;
            case 'c':
              i = 0;
              while (pdkim_combined_canons[i].str != NULL) {
                if (strcmp(cur_val->str,pdkim_combined_canons[i].str) == 0 ) {
                  sig->canon_headers = pdkim_combined_canons[i].canon_headers;
                  sig->canon_body    = pdkim_combined_canons[i].canon_body;
                  break;
                }
                i++;
              }
            break;
            case 'q':
              i = 0;
              while (pdkim_querymethods[i] != NULL) {
                if (strcmp(cur_val->str,pdkim_querymethods[i]) == 0 ) {
                  sig->querymethod = i;
                  break;
                }
                i++;
              }
            break;
            case 's':
              sig->selector = strdup(cur_val->str);
            break;
            case 'd':
              sig->domain = strdup(cur_val->str);
            break;
            case 'i':
              sig->identity = pdkim_decode_qp(cur_val->str);
            break;
            case 't':
              sig->created = strtoul(cur_val->str,NULL,10);
            break;
            case 'x':
              sig->expires = strtoul(cur_val->str,NULL,10);
            break;
            case 'l':
              sig->bodylength = strtoul(cur_val->str,NULL,10);
            break;
            case 'h':
              sig->headernames = strdup(cur_val->str);
            break;
            case 'z':
              sig->copiedheaders = pdkim_decode_qp(cur_val->str);
            break;
            default:
              #ifdef PDKIM_DEBUG
              if (ctx->debug_stream)
                fprintf(ctx->debug_stream, "Unknown tag encountered\n");
              #endif
            break;
          }
        }
        pdkim_strclear(cur_tag);
        pdkim_strclear(cur_val);
        in_b_val = 0;
        where = PDKIM_HDR_LIMBO;
        goto NEXT_CHAR;
      }
      else pdkim_strncat(cur_val,p,1);
    }

    NEXT_CHAR:

    if (!in_b_val) {
      *q = *p;
      q++;
    }
    p++;
  }

  /* Make sure the most important bits are there. */
  if (!(sig->domain      && (*(sig->domain)      != '\0') &&
        sig->selector    && (*(sig->selector)    != '\0') &&
        sig->headernames && (*(sig->headernames) != '\0') &&
        sig->bodyhash    &&
        sig->sigdata     &&
        sig->version)) {
    pdkim_free_sig(sig);
    return NULL;
  }

  *q = '\0';
  #ifdef PDKIM_DEBUG
  if (ctx->debug_stream) {
    fprintf(ctx->debug_stream,
            "PDKIM >> Raw signature w/o b= tag value >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    pdkim_quoteprint(ctx->debug_stream,
                     sig->rawsig_no_b_val,
                     strlen(sig->rawsig_no_b_val), 1);
    fprintf(ctx->debug_stream,
            "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
  }
  #endif

  sha1_starts(&(sig->sha1_body));
  sha2_starts(&(sig->sha2_body),0);

  return sig;
}


/* -------------------------------------------------------------------------- */
pdkim_pubkey *pdkim_parse_pubkey_record(pdkim_ctx *ctx, char *raw_record) {
  pdkim_pubkey *pub ;
  char *p;
  pdkim_str *cur_tag = NULL;
  pdkim_str *cur_val = NULL;
  int where = PDKIM_HDR_LIMBO;

  pub = malloc(sizeof(pdkim_pubkey));
  if (pub == NULL) return NULL;
  memset(pub,0,sizeof(pdkim_pubkey));

  p = raw_record;

  while (*p != '\0') {

    /* Ignore FWS */
    if ( (*p == '\r') || (*p == '\n') )
      goto NEXT_CHAR;

    if (where == PDKIM_HDR_LIMBO) {
      /* In limbo, just wait for a tag-char to appear */
      if (!((*p >= 'a') && (*p <= 'z')))
        goto NEXT_CHAR;

      where = PDKIM_HDR_TAG;
    }

    if (where == PDKIM_HDR_TAG) {
      if (cur_tag == NULL)
        cur_tag = pdkim_strnew(NULL);

      if ((*p >= 'a') && (*p <= 'z'))
        pdkim_strncat(cur_tag,p,1);

      if (*p == '=') {
        where = PDKIM_HDR_VALUE;
        goto NEXT_CHAR;
      }
    }

    if (where == PDKIM_HDR_VALUE) {
      if (cur_val == NULL)
        cur_val = pdkim_strnew(NULL);

      if ( (*p == '\r') || (*p == '\n') )
        goto NEXT_CHAR;

      if (*p == ';') {
        if (cur_tag->len > 0) {
          pdkim_strtrim(cur_val);
          #ifdef PDKIM_DEBUG
          if (ctx->debug_stream)
            fprintf(ctx->debug_stream, "%s=%s\n", cur_tag->str, cur_val->str);
          #endif
          switch (cur_tag->str[0]) {
            case 'v':
              /* This tag isn't evaluated because:
                 - We only support version DKIM1.
                 - Which is the default for this value (set below)
                 - Other versions are currently not specified.      */
            break;
            case 'h':
              pub->hashes = strdup(cur_val->str);
            break;
            case 'g':
              pub->granularity = strdup(cur_val->str);
            break;
            case 'n':
              pub->notes = pdkim_decode_qp(cur_val->str);
            break;
            case 'p':
              pub->key = pdkim_decode_base64(cur_val->str,&(pub->key_len));
            break;
            case 'k':
              pub->hashes = strdup(cur_val->str);
            break;
            case 's':
              pub->srvtype = strdup(cur_val->str);
            break;
            case 't':
              if (strchr(cur_val->str,'t') != NULL) pub->testing = 1;
              if (strchr(cur_val->str,'s') != NULL) pub->no_subdomaining = 1;
            break;
            default:
              #ifdef PDKIM_DEBUG
              if (ctx->debug_stream)
                fprintf(ctx->debug_stream, "Unknown tag encountered\n");
              #endif
            break;
          }
        }
        pdkim_strclear(cur_tag);
        pdkim_strclear(cur_val);
        where = PDKIM_HDR_LIMBO;
        goto NEXT_CHAR;
      }
      else pdkim_strncat(cur_val,p,1);
    }

    NEXT_CHAR:
    p++;
  }

  /* Set fallback defaults */
  if (pub->version     == NULL) pub->version     = strdup(PDKIM_PUB_RECORD_VERSION);
  if (pub->granularity == NULL) pub->granularity = strdup("*");
  if (pub->keytype     == NULL) pub->keytype     = strdup("rsa");
  if (pub->srvtype     == NULL) pub->srvtype     = strdup("*");

  /* p= is required */
  if (pub->key == NULL) {
    pdkim_free_pubkey(pub);
    return NULL;
  }

  return pub;
}


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
        relaxed_data = malloc(len+1);
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

    /* Finish hashes */
    unsigned char bh[32]; /* SHA-256 = 32 Bytes,  SHA-1 = 20 Bytes */
    if (sig->algo == PDKIM_ALGO_RSA_SHA1)
      sha1_finish(&(sig->sha1_body),bh);
    else
      sha2_finish(&(sig->sha2_body),bh);

    #ifdef PDKIM_DEBUG
    if (ctx->debug_stream) {
      fprintf(ctx->debug_stream, "PDKIM [%s] Body bytes hashed: %lu\n",
        sig->domain, sig->signed_body_bytes);
      fprintf(ctx->debug_stream, "PDKIM [%s] bh  computed: ", sig->domain);
      pdkim_hexprint(ctx->debug_stream, (char *)bh,
                     (sig->algo == PDKIM_ALGO_RSA_SHA1)?20:32,1);
    }
    #endif

    /* SIGNING -------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {
      sig->bodyhash_len = (sig->algo == PDKIM_ALGO_RSA_SHA1)?20:32;
      sig->bodyhash = malloc(sig->bodyhash_len);
      if (sig->bodyhash == NULL) return PDKIM_ERR_OOM;
      memcpy(sig->bodyhash,bh,sig->bodyhash_len);

      /* If bodylength limit is set, and we have received less bytes
         than the requested amount, effectively remove the limit tag. */
      if (sig->signed_body_bytes < sig->bodylength) sig->bodylength = 0;
    }
    /* VERIFICATION --------------------------------------------------------- */
    else {
      /* Compare bodyhash */
      if (memcmp(bh,sig->bodyhash,
                 (sig->algo == PDKIM_ALGO_RSA_SHA1)?20:32) == 0) {
        #ifdef PDKIM_DEBUG
        if (ctx->debug_stream)
          fprintf(ctx->debug_stream, "PDKIM [%s] Body hash verified OK\n",
                  sig->domain);
        #endif
      }
      else {
        #ifdef PDKIM_DEBUG
        if (ctx->debug_stream) {
          fprintf(ctx->debug_stream, "PDKIM [%s] Body hash did NOT verify\n",
                  sig->domain);
          fprintf(ctx->debug_stream, "PDKIM [%s] bh signature: ", sig->domain);
          pdkim_hexprint(ctx->debug_stream, sig->bodyhash,
                           (sig->algo == PDKIM_ALGO_RSA_SHA1)?20:32,1);
        }
        #endif
        sig->verify_status     = PDKIM_VERIFY_FAIL;
        sig->verify_ext_status = PDKIM_VERIFY_FAIL_BODY;
      }
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
#define DKIM_SIGNATURE_HEADERNAME "DKIM-Signature:"
int pdkim_header_complete(pdkim_ctx *ctx) {
  pdkim_signature *sig = ctx->sig;

  /* Special case: The last header can have an extra \r appended */
  if ( (ctx->cur_header->len > 1) &&
       (ctx->cur_header->str[(ctx->cur_header->len)-1] == '\r') ) {
    ctx->cur_header->str[(ctx->cur_header->len)-1] = '\0';
    ctx->cur_header->len--;
  }

  ctx->num_headers++;
  if (ctx->num_headers > PDKIM_MAX_HEADERS) goto BAIL;

  /* Traverse all signatures */
  while (sig != NULL) {

    /* SIGNING -------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {
      if (header_name_match(ctx->cur_header->str,
                            sig->sign_headers?
                              sig->sign_headers:
                              PDKIM_DEFAULT_SIGN_HEADERS, 0) < 0) goto NEXT_SIG;
    }
    /* VERIFICATION --------------------------------------------------------- */
    else {
      int rc = header_name_match(ctx->cur_header->str,
                                 sig->headernames,
                                 sig->headernames_pos);
      /* Header is not included or out-of-sequence */
      if (rc < 0) goto NEXT_SIG;
      sig->headernames_pos = rc;
    }

    /* Add header to the signed headers list */
    pdkim_stringlist *list = pdkim_append_stringlist(sig->headers,
                                                     ctx->cur_header->str);
    if (list == NULL) return PDKIM_ERR_OOM;
    sig->headers = list;

    NEXT_SIG:
    sig = sig->next;
  }

  /* DKIM-Signature: headers are added to the verification list */
  if ( (ctx->mode == PDKIM_MODE_VERIFY) &&
       (strncasecmp(ctx->cur_header->str,
                    DKIM_SIGNATURE_HEADERNAME,
                    strlen(DKIM_SIGNATURE_HEADERNAME)) == 0) ) {
    /* Create and chain new signature block */
    #ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
        "PDKIM >> Found sig, trying to parse >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
    #endif
    pdkim_signature *new_sig = pdkim_parse_sig_header(ctx, ctx->cur_header->str);
    if (new_sig != NULL) {
      pdkim_signature *last_sig = ctx->sig;
      if (last_sig == NULL) {
        ctx->sig = new_sig;
      }
      else {
        while (last_sig->next != NULL) { last_sig = last_sig->next; };
        last_sig->next = new_sig;
      }
    }
    else {
      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream) {
        fprintf(ctx->debug_stream,"Error while parsing signature header\n");
        fprintf(ctx->debug_stream,
          "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      }
      #endif
    }
  }

  BAIL:
  pdkim_strclear(ctx->cur_header); /* Re-use existing pdkim_str */
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
      if (ctx->cur_header->len < PDKIM_MAX_HEADER_LEN)
        if (pdkim_strncat(ctx->cur_header,&data[p],1) == NULL)
          return PDKIM_ERR_OOM;
    }
  }
  return PDKIM_OK;
};


/* -------------------------------------------------------------------------- */
char *pdkim_create_header(pdkim_signature *sig, int final) {
  char *rc = NULL;
  char *base64_bh = NULL;
  char *base64_b  = NULL;
  pdkim_str *hdr = pdkim_strnew("DKIM-Signature: v="PDKIM_SIGNATURE_VERSION);
  if (hdr == NULL) return NULL;

  base64_bh = pdkim_encode_base64(sig->bodyhash, sig->bodyhash_len);
  if (base64_bh == NULL) goto BAIL;

  /* Required and static bits */
  if (
        pdkim_strcat(hdr,"; a=")                                &&
        pdkim_strcat(hdr,pdkim_algos[sig->algo])                &&
        pdkim_strcat(hdr,"; q=")                                &&
        pdkim_strcat(hdr,pdkim_querymethods[sig->querymethod])  &&
        pdkim_strcat(hdr,"; c=")                                &&
        pdkim_strcat(hdr,pdkim_canons[sig->canon_headers])      &&
        pdkim_strcat(hdr,"/")                                   &&
        pdkim_strcat(hdr,pdkim_canons[sig->canon_body])         &&
        pdkim_strcat(hdr,"; d=")                                &&
        pdkim_strcat(hdr,sig->domain)                           &&
        pdkim_strcat(hdr,"; s=")                                &&
        pdkim_strcat(hdr,sig->selector)                         &&
        pdkim_strcat(hdr,";\r\n\th=")                           &&
        pdkim_strcat(hdr,sig->headernames)                      &&
        pdkim_strcat(hdr,"; bh=")                               &&
        pdkim_strcat(hdr,base64_bh)                             &&
        pdkim_strcat(hdr,";\r\n\t")
     ) {
    /* Optional bits */
    if (sig->identity != NULL) {
      if (!( pdkim_strcat(hdr,"i=")                             &&
             pdkim_strcat(hdr,sig->identity)                    &&
             pdkim_strcat(hdr,";") ) ) {
        goto BAIL;
      }
    }
    if (sig->created > 0) {
      if (!( pdkim_strcat(hdr,"t=")                             &&
             pdkim_numcat(hdr,sig->created)                     &&
             pdkim_strcat(hdr,";") ) ) {
        goto BAIL;
      }
    }
    if (sig->expires > 0) {
      if (!( pdkim_strcat(hdr,"x=")                             &&
             pdkim_numcat(hdr,sig->expires)                     &&
             pdkim_strcat(hdr,";") ) ) {
        goto BAIL;
      }
    }
    if (sig->bodylength > 0) {
      if (!( pdkim_strcat(hdr,"l=")                             &&
             pdkim_numcat(hdr,sig->bodylength)                  &&
             pdkim_strcat(hdr,";") ) ) {
        goto BAIL;
      }
    }
    /* Extra linebreak */
    if (hdr->str[(hdr->len)-1] == ';') {
      if (!pdkim_strcat(hdr," \r\n\t")) goto BAIL;
    }
    /* Preliminary or final version? */
    if (final) {
      base64_b = pdkim_encode_base64(sig->sigdata, sig->sigdata_len);
      if (base64_b == NULL) goto BAIL;
      if (
            pdkim_strcat(hdr,"b=")                              &&
            pdkim_strcat(hdr,base64_b)                          &&
            pdkim_strcat(hdr,";")
         ) goto DONE;
    }
    else {
      if (pdkim_strcat(hdr,"b=;")) goto DONE;
    }

    goto BAIL;
  }

  DONE:
  rc = strdup(hdr->str);

  BAIL:
  pdkim_strfree(hdr);
  if (base64_bh != NULL) free(base64_bh);
  if (base64_b  != NULL) free(base64_b);
  return rc;
}


/* -------------------------------------------------------------------------- */
int pdkim_feed_finish(pdkim_ctx *ctx, char **signature) {
  pdkim_signature *sig = ctx->sig;
  pdkim_str *headernames = NULL;             /* Collected signed header names */

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

  /* Build (and/or evaluate) body hash */
  if (pdkim_finish_bodyhash(ctx) != PDKIM_OK) return PDKIM_ERR_OOM;

  /* SIGNING -------------------------------------------------------------- */
  if (ctx->mode == PDKIM_MODE_SIGN) {
    headernames = pdkim_strnew(NULL);
    if (headernames == NULL) return PDKIM_ERR_OOM;
  }
  /* ---------------------------------------------------------------------- */

  while (sig != NULL) {
    sha1_context sha1_headers;
    sha2_context sha2_headers;
    pdkim_stringlist *p = sig->headers;
    char *sig_hdr;
    char headerhash[32];

    if (sig->algo == PDKIM_ALGO_RSA_SHA1)
      sha1_starts(&sha1_headers);
    else
      sha2_starts(&sha2_headers,0);

    #ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
              "PDKIM >> Hashed header data, canonicalized, in sequence >>>>>>>>>>>>>>\n");
    #endif

    while (p != NULL) {
      char *rh;

      /* SIGNING -------------------------------------------------------------- */
      if (ctx->mode == PDKIM_MODE_SIGN) {
        /* Collect header names (Note: colon presence is guaranteed here) */
        char *q = strchr(p->value,':');
        if (pdkim_strncat(headernames, p->value,
                          (q-(p->value))+((p->next==NULL)?0:1)) == NULL)
          return PDKIM_ERR_OOM;
      }
      /* ---------------------------------------------------------------------- */

      if (sig->canon_body == PDKIM_CANON_RELAXED)
        rh = pdkim_relax_header(p->value,1); /* cook header for relaxed canon */
      else
        rh = strdup(p->value);               /* just copy it for simple canon */

      if (rh == NULL) return PDKIM_ERR_OOM;

      /* Feed header to the hash algorithm */
      if (sig->algo == PDKIM_ALGO_RSA_SHA1)
        sha1_update(&(sha1_headers),(unsigned char *)rh,strlen(rh));
      else
        sha2_update(&(sha2_headers),(unsigned char *)rh,strlen(rh));
      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream)
        pdkim_quoteprint(ctx->debug_stream, rh, strlen(rh), 1);
      #endif
      free(rh);
      p = p->next;
    }

    #ifdef PDKIM_DEBUG
    if (ctx->debug_stream)
      fprintf(ctx->debug_stream,
              "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    #endif


    /* SIGNING ---------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {
      /* Copy headernames to signature struct */
      sig->headernames = strdup(headernames->str);
      pdkim_strfree(headernames);

      /* Create signature header with b= omitted */
      sig_hdr = pdkim_create_header(ctx->sig,0);
    }
    /* VERIFICATION ----------------------------------------------------------- */
    else {
      sig_hdr = strdup(sig->rawsig_no_b_val);
    }
    /* ------------------------------------------------------------------------ */

    if (sig_hdr == NULL) return PDKIM_ERR_OOM;

    /* Relax header if necessary */
    if (sig->canon_headers == PDKIM_CANON_RELAXED) {
      char *relaxed_hdr = pdkim_relax_header(sig_hdr,0);
      free(sig_hdr);
      if (relaxed_hdr == NULL) return PDKIM_ERR_OOM;
      sig_hdr = relaxed_hdr;
    }

    #ifdef PDKIM_DEBUG
    if (ctx->debug_stream) {
      fprintf(ctx->debug_stream,
              "PDKIM >> Signed DKIM-Signature header, canonicalized >>>>>>>>>>>>>>>>>\n");
      pdkim_quoteprint(ctx->debug_stream, sig_hdr, strlen(sig_hdr), 1);
      fprintf(ctx->debug_stream,
              "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    }
    #endif

    /* Finalize header hash */
    if (sig->algo == PDKIM_ALGO_RSA_SHA1) {
      sha1_update(&(sha1_headers),(unsigned char *)sig_hdr,strlen(sig_hdr));
      sha1_finish(&(sha1_headers),(unsigned char *)headerhash);
    }
    else {
      sha2_update(&(sha2_headers),(unsigned char *)sig_hdr,strlen(sig_hdr));
      sha2_finish(&(sha2_headers),(unsigned char *)headerhash);
    }

    free(sig_hdr);

    /* SIGNING ---------------------------------------------------------------- */
    if (ctx->mode == PDKIM_MODE_SIGN) {
      rsa_context rsa;

      rsa_init(&rsa,RSA_PKCS_V15,0,NULL,NULL);

      /* Perform private key operation */
      if (rsa_parse_key(&rsa, (unsigned char *)sig->rsa_privkey,
                        strlen(sig->rsa_privkey), NULL, 0) != 0) {
        return PDKIM_ERR_RSA_PRIVKEY;
      }

      sig->sigdata_len = mpi_size(&(rsa.N));
      sig->sigdata = malloc(sig->sigdata_len);
      if (sig->sigdata == NULL) return PDKIM_ERR_OOM;

      if (rsa_pkcs1_sign( &rsa, RSA_PRIVATE,
                          ((sig->algo == PDKIM_ALGO_RSA_SHA1)?
                             RSA_SHA1:RSA_SHA256),
                          0,
                          (unsigned char *)headerhash,
                          (unsigned char *)sig->sigdata ) != 0) {
        return PDKIM_ERR_RSA_SIGNING;
      }

      rsa_free(&rsa);

      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream) {
        fprintf(ctx->debug_stream, "PDKIM [%s] b computed: ",
                sig->domain);
        pdkim_hexprint(ctx->debug_stream, sig->sigdata, sig->sigdata_len, 1);
      }
      #endif

      /* Recreate signature header with b= included, return it to the caller */
      if (signature != NULL) {
        *signature = pdkim_create_header(ctx->sig,1);
        if (*signature == NULL) return PDKIM_ERR_OOM;
      }
    }
    /* VERIFICATION ----------------------------------------------------------- */
    else {
      rsa_context rsa;
      char *dns_txt_name, *dns_txt_reply;

      rsa_init(&rsa,RSA_PKCS_V15,0,NULL,NULL);

      dns_txt_name  = malloc(PDKIM_DNS_TXT_MAX_NAMELEN);
      if (dns_txt_name == NULL) return PDKIM_ERR_OOM;
      dns_txt_reply = malloc(PDKIM_DNS_TXT_MAX_RECLEN);
      if (dns_txt_reply == NULL) {
        free(dns_txt_name);
        return PDKIM_ERR_OOM;
      }
      memset(dns_txt_reply,0,PDKIM_DNS_TXT_MAX_RECLEN);
      memset(dns_txt_name ,0,PDKIM_DNS_TXT_MAX_NAMELEN);

      if (snprintf(dns_txt_name,PDKIM_DNS_TXT_MAX_NAMELEN,
                   "%s._domainkey.%s.",
                   sig->selector,sig->domain) >= PDKIM_DNS_TXT_MAX_NAMELEN) {
        sig->verify_status =      PDKIM_VERIFY_INVALID;
        sig->verify_ext_status =  PDKIM_VERIFY_INVALID_BUFFER_SIZE;
        goto NEXT_VERIFY;
      };

      if ((ctx->dns_txt_callback(dns_txt_name, dns_txt_reply) != PDKIM_OK) ||
          (dns_txt_reply[0] == '\0')) {
        sig->verify_status =      PDKIM_VERIFY_INVALID;
        sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_UNAVAILABLE;
        goto NEXT_VERIFY;
      }

      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream) {
        fprintf(ctx->debug_stream,
                "PDKIM >> Parsing public key record >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
        fprintf(ctx->debug_stream,"Raw record: ");
        pdkim_quoteprint(ctx->debug_stream, dns_txt_reply, strlen(dns_txt_reply), 1);
      }
      #endif

      sig->pubkey = pdkim_parse_pubkey_record(ctx,dns_txt_reply);
      if (sig->pubkey == NULL) {
        sig->verify_status =      PDKIM_VERIFY_INVALID;
        sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_PARSING;
        #ifdef PDKIM_DEBUG
        if (ctx->debug_stream) {
          fprintf(ctx->debug_stream,"Error while parsing public key record\n");
          fprintf(ctx->debug_stream,
            "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
        }
        #endif
        goto NEXT_VERIFY;
      }

      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream) {
        fprintf(ctx->debug_stream,
          "PDKIM <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
      }
      #endif

      if (rsa_parse_public_key(&rsa,
                              (unsigned char *)sig->pubkey->key,
                               sig->pubkey->key_len) != 0) {
        sig->verify_status =      PDKIM_VERIFY_INVALID;
        sig->verify_ext_status =  PDKIM_VERIFY_INVALID_PUBKEY_PARSING;
        goto NEXT_VERIFY;
      }

      /* Check the signature */
      if (rsa_pkcs1_verify(&rsa,
                        RSA_PUBLIC,
                        ((sig->algo == PDKIM_ALGO_RSA_SHA1)?
                             RSA_SHA1:RSA_SHA256),
                        0,
                        (unsigned char *)headerhash,
                        (unsigned char *)sig->sigdata) != 0) {
        sig->verify_status =      PDKIM_VERIFY_FAIL;
        sig->verify_ext_status =  PDKIM_VERIFY_FAIL_MESSAGE;
        #ifdef PDKIM_DEBUG
        if (ctx->debug_stream) {
          fprintf(ctx->debug_stream, "PDKIM [%s] signature did NOT verify OK\n",
                  sig->domain);
        }
        #endif
        goto NEXT_VERIFY;
      }

      /* We have a winner! */
      sig->verify_status = PDKIM_VERIFY_PASS;

      #ifdef PDKIM_DEBUG
      if (ctx->debug_stream) {
        fprintf(ctx->debug_stream, "PDKIM [%s] signature verified OK\n",
                sig->domain);
      }
      #endif

      NEXT_VERIFY:
      rsa_free(&rsa);
      free(dns_txt_name);
      free(dns_txt_reply);
    }

    sig = sig->next;
  }

  return PDKIM_OK;
}


/* -------------------------------------------------------------------------- */
pdkim_ctx *pdkim_init_verify(int input_mode,
                             int(*dns_txt_callback)(char *, char *)
                             ) {
  pdkim_ctx *ctx = malloc(sizeof(pdkim_ctx));
  if (ctx == NULL) return NULL;
  memset(ctx,0,sizeof(pdkim_ctx));
  ctx->mode = PDKIM_MODE_VERIFY;
  ctx->input_mode = input_mode;
  ctx->dns_txt_callback = dns_txt_callback;

  return ctx;
}


/* -------------------------------------------------------------------------- */
pdkim_ctx *pdkim_init_sign(int input_mode,
                           char *domain,
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
  ctx->input_mode = input_mode;
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

  ctx->sig->canon_headers = canon_headers;
  ctx->sig->canon_body = canon_body;
  ctx->sig->bodylength = bodylength;
  ctx->sig->algo = algo;
  ctx->sig->created = created;
  ctx->sig->expires = expires;

  return PDKIM_OK;
};


/* -------------------------------------------------------------------------- */
void pdkim_free_pubkey(pdkim_pubkey *pub) {
  if (pub) {
    if (pub->version        != NULL) free(pub->version);
    if (pub->granularity    != NULL) free(pub->granularity);
    if (pub->hashes         != NULL) free(pub->hashes);
    if (pub->keytype        != NULL) free(pub->keytype);
    if (pub->srvtype        != NULL) free(pub->srvtype);
    if (pub->notes          != NULL) free(pub->notes);
    if (pub->key            != NULL) free(pub->key);
    free(pub);
  }
}


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

    if (sig->pubkey != NULL) pdkim_free_pubkey(sig->pubkey);

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
