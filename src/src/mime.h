/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2004, 2015 */
/* License: GPL */

#ifdef WITH_CONTENT_SCAN

#define MIME_MAX_HEADER_SIZE 8192
#define MIME_MAX_LINE_LENGTH 32768

#define MBC_ATTACHMENT            0
#define MBC_COVERLETTER_ONESHOT   1
#define MBC_COVERLETTER_ALL       2

struct mime_boundary_context
{
  struct mime_boundary_context *parent;
  unsigned char *boundary;
  int context;
};

typedef struct mime_header {
  uschar *  name;
  int       namelen;
  uschar ** value;
} mime_header;

static mime_header mime_header_list[] = {
  { US"content-type:",              13, &mime_content_type },
  { US"content-disposition:",       20, &mime_content_disposition },
  { US"content-transfer-encoding:", 26, &mime_content_transfer_encoding },
  { US"content-id:",                11, &mime_content_id },
  { US"content-description:",       20, &mime_content_description }
};

static int mime_header_list_size = sizeof(mime_header_list)/sizeof(mime_header);



typedef struct mime_parameter {
  uschar *  name;
  int       namelen;
  uschar ** value;
} mime_parameter;

static mime_parameter mime_parameter_list[] = {
  { US"name=",     5, &mime_filename },
  { US"filename=", 9, &mime_filename },
  { US"charset=",  8, &mime_charset  },
  { US"boundary=", 9, &mime_boundary }
};


/* MIME Anomaly list */
#define MIME_ANOMALY_BROKEN_BASE64    2, "Broken BASE64 encoding detected"
#define MIME_ANOMALY_BROKEN_QP        1, "Broken Quoted-Printable encoding detected"


/* BASE64 decoder matrix */
static unsigned char mime_b64[256]={
/*   0 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  16 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  32 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,   62,  128,  128,  128,   63,
/*  48 */   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,  128,  128,  128,  255,  128,  128,
/*  64 */  128,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
/*  80 */   15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,  128,  128,  128,  128,  128,
/*  96 */  128,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
/* 112 */   41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,  128,  128,  128,  128,  128,
/* 128 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 144 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 160 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 176 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 192 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 208 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 224 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/* 240 */  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128
};

#endif
