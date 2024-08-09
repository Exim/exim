/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2009 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Private structure for the private options. */

typedef struct {
  uschar *from;
  uschar *reply_to;
  uschar *to;
  uschar *cc;
  uschar *bcc;
  uschar *subject;
  uschar *headers;
  uschar *text;
  uschar *file;
  uschar *logfile;
  uschar *oncelog;
  uschar *once_repeat;
  uschar *never_mail;
  int   mode;
  off_t once_file_size;
  BOOL  file_expand;
  BOOL  file_optional;
  BOOL  return_message;
} autoreply_transport_options_block;

/* Data for reading the private options. */

extern optionlist autoreply_transport_options[];
extern int autoreply_transport_options_count;

/* Block containing default values. */

extern autoreply_transport_options_block autoreply_transport_option_defaults;

/* The main and init entry points for the transport */

extern void autoreply_transport_init(driver_instance *);
extern BOOL autoreply_transport_entry(transport_instance *, address_item *);

/* End of transports/autoreply.h */
