/* $Cambridge: exim/src/src/routers/accept.h,v 1.4 2006/02/07 11:19:02 ph10 Exp $ */

/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2006 */
/* See the file NOTICE for conditions of use and distribution. */

/* Private structure for the private options (there aren't any). */

typedef struct {
  uschar *dummy;
} accept_router_options_block;

/* Data for reading the private options. */

extern optionlist accept_router_options[];
extern int accept_router_options_count;

/* Block containing default values. */

extern accept_router_options_block accept_router_option_defaults;

/* The main and initialization entry points for the router */

extern int accept_router_entry(router_instance *, address_item *,
  struct passwd *, int, address_item **, address_item **,
  address_item **, address_item **);

extern void accept_router_init(router_instance *);

/* End of routers/accept.h */
