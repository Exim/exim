/* $Cambridge: exim/src/src/dk.h,v 1.2 2006/02/07 11:19:00 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2006 */
/* See the file NOTICE for conditions of use and distribution. */

/* Code for DomainKeys support. Other DK relevant code is in
   receive.c, transport.c and transports/smtp.c */

#ifdef EXPERIMENTAL_DOMAINKEYS

#include <domainkeys.h>

#define DK_EXIM_ADDRESS_NONE        0
#define DK_EXIM_ADDRESS_FROM_FROM   1
#define DK_EXIM_ADDRESS_FROM_SENDER 2

#define DK_EXIM_RESULT_ERR              0
#define DK_EXIM_RESULT_BAD_FORMAT       1
#define DK_EXIM_RESULT_NO_KEY           2
#define DK_EXIM_RESULT_NO_SIGNATURE     3
#define DK_EXIM_RESULT_REVOKED          4
#define DK_EXIM_RESULT_NON_PARTICIPANT  5
#define DK_EXIM_RESULT_GOOD             6
#define DK_EXIM_RESULT_BAD              7

typedef struct dk_exim_verify_block {
  int     result;
  int     address_source;
  uschar *result_string;
  uschar *address;
  uschar *domain;
  uschar *local_part;
  BOOL    is_signed;
  BOOL    signsall;
  BOOL    testing;
} dk_exim_verify_block;

int     dk_receive_getc(void);
int     dk_receive_ungetc(int);
void    dk_exim_verify_init(void);
void    dk_exim_verify_finish(void);
int     dk_exim_verify_result(uschar **);
uschar *dk_exim_sign(int, uschar *, uschar *, uschar *, uschar *);

extern  dk_exim_verify_block *dk_verify_block;

#endif
