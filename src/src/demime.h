/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) Tom Kistner <tom@duncanthrax.net> 2003-???? */
/* License: GPL */

/* demime defines */

#ifdef WITH_OLD_DEMIME

#define MIME_DEMUX_MODE_SCANNING     0
#define MIME_DEMUX_MODE_MIME_HEADERS 1
#define MIME_DEMUX_MODE_BASE64       2
#define MIME_DEMUX_MODE_QP           3
#define MIME_DEMUX_MODE_PLAIN        4

#define MIME_UU_MODE_OFF             0
#define MIME_UU_MODE_UNCONFIRMED     1
#define MIME_UU_MODE_CONFIRMED       2

#define MIME_MAX_EXTENSION 128

#define MIME_READ_LINE_EOF 0
#define MIME_READ_LINE_OK 1
#define MIME_READ_LINE_OVERFLOW 2

#define MIME_SANITY_MAX_LINE_LENGTH 131071
#define MIME_SANITY_MAX_FILENAME 512
#define MIME_SANITY_MAX_HEADER_OPTION_VALUE 1024
#define MIME_SANITY_MAX_B64_LINE_LENGTH 76
#define MIME_SANITY_MAX_BOUNDARY_LENGTH 1024
#define MIME_SANITY_MAX_DUMP_FILES 1024



/* MIME errorlevel settings */

#define MIME_ERRORLEVEL_LONG_LINE        3,US"line length in message or single header size exceeds %u bytes",MIME_SANITY_MAX_LINE_LENGTH
#define MIME_ERRORLEVEL_TOO_MANY_PARTS   3,US"too many MIME parts (max %u)",MIME_SANITY_MAX_DUMP_FILES
#define MIME_ERRORLEVEL_MESSAGE_PARTIAL  3,US"'message/partial' MIME type"
#define MIME_ERRORLEVEL_FILENAME_LENGTH  3,US"proposed filename exceeds %u characters",MIME_SANITY_MAX_FILENAME
#define MIME_ERRORLEVEL_BOUNDARY_LENGTH  3,US"boundary length exceeds %u characters",MIME_SANITY_MAX_BOUNDARY_LENGTH
#define MIME_ERRORLEVEL_DOUBLE_HEADERS   2,US"double headers (content-type, content-disposition or content-transfer-encoding)"
#define MIME_ERRORLEVEL_UU_MISALIGNED    1,US"uuencoded line length is not a multiple of 4 characters"
#define MIME_ERRORLEVEL_UU_LINE_LENGTH   1,US"uuencoded line length does not match advertised number of bytes"
#define MIME_ERRORLEVEL_B64_LINE_LENGTH  1,US"base64 line length exceeds %u characters",MIME_SANITY_MAX_B64_LINE_LENGTH
#define MIME_ERRORLEVEL_B64_ILLEGAL_CHAR 2,US"base64 line contains illegal character"
#define MIME_ERRORLEVEL_B64_MISALIGNED   1,US"base64 line length is not a multiple of 4 characters"
#define MIME_ERRORLEVEL_QP_ILLEGAL_CHAR  1,US"quoted-printable encoding contains illegal character"


/* demime structures */

typedef struct mime_part {
  /* true if there was a content-type header */
  int seen_content_type;
  /* true if there was a content-transfer-encoding header
     contains the encoding type */
  int seen_content_transfer_encoding;
  /* true if there was a content-disposition header */
  int seen_content_disposition;
  /* pointer to a buffer with the proposed file extension */
  uschar *extension;
} mime_part;

typedef struct boundary {
  struct boundary *next;
  uschar *boundary_string;
} boundary;

typedef struct file_extension {
  struct file_extension *next;
  uschar *file_extension_string;
} file_extension;

/* demime.c prototypes */

unsigned int mime_hstr_i(uschar *);
uschar      *mime_decode_qp(uschar *, int *);
int          mime_get_dump_file(uschar *, FILE **, uschar *);
int          mime_header_find(uschar *, uschar *, uschar **);
int          mime_read_line(FILE *, int, uschar *, long *);
int          mime_check_boundary(uschar *, struct boundary *);
int          mime_check_uu_start(uschar *, uschar *, int *);
long         uu_decode_line(uschar *, uschar **, long, uschar *);
long         mime_decode_line(int ,uschar *, uschar **, long, uschar *);
void         mime_trigger_error(int, uschar *, ...);
int          mime_demux(FILE *, uschar *);



/* BASE64 decoder matrix */
static unsigned char b64[256]={
/*   0 */ 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  16 */ 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
/*  32 */ 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,   62,  128,  128,  128,   63,
/*  48 */  52,   53,   54,   55,   56,   57,   58,   59,   60,   61,  128,  128,  128,  255,  128,  128,
/*  64 */ 128,    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,
/*  80 */  15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,  128,  128,  128,  128,  128,
/*  96 */ 128,   26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,
  41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,
 128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128,  128
};


/* Microsoft-Style uudecode matrix */
static unsigned char uudec[256]={
/*   0 */   0,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,
/*  16 */  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,
/*  32 */   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,
/*  48 */  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,
/*  64 */  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,
/*  80 */  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,
/*  96 */   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,
/* 112 */  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,
/* 128 */  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,
/* 144 */  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,
/* 160 */   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,
/* 176 */  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31,
/* 192 */  32,   33,   34,   35,   36,   37,   38,   39,   40,   41,   42,   43,   44,   45,   46,   47,
/* 208 */  48,   49,   50,   51,   52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   62,   63,
/* 224 */   0,    1,    2,    3,    4,    5,    6,    7,    8,    9,   10,   11,   12,   13,   14,   15,
/* 240 */  16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,   29,   30,   31
};

#endif
