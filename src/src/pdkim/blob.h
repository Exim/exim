/*
 *  PDKIM - a RFC4871 (DKIM) implementation
 *
 *  Copyright (C) 2016  Exim maintainers
 *
 *  RSA signing/verification interface
 */

#ifndef BLOB_H	/* entire file */
#define BLOB_H

typedef struct {
  uschar * data;
  size_t   len;
} blob;

#endif
