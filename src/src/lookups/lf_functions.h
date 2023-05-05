/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* Copyright (c) The Exim Maintainers 2022 */
/* See the file NOTICE for conditions of use and distribution. */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Header for the functions that are shared by the lookups */

extern int     lf_check_file(int, const uschar *, int, int, uid_t *, gid_t *,
                 const char *, uschar **);
extern gstring *lf_quote(uschar *, uschar *, int, gstring *);
extern int     lf_sqlperform(const uschar *, const uschar *, const uschar *,
		 const uschar *, uschar **,
                 uschar **, uint *, const uschar *,
		 int(*)(const uschar *, uschar *, uschar **,
                 uschar **, BOOL *, uint *, const uschar *));

/*
  The st_mode field returned by stat() indicates the type of a file; these
  functions help to interpret that.

  Usage:
   struct stat s;
   const uschar *t;
   stat(&s, filename);
   if ((t = S_IFMT_to_long_name(s.st_mode)))
     printf("%s is a %s\n", filename, t);
   else
     printf("%s is unknown\n", filename);
   if ( allowed_filetype_mask & S_IFMT_to_set(s.st_mode) )
     printf("\tALLOWED\n");
   else
     printf("\tFORBIDDEN\n");

  S_IFMT_to_index shifts this to remove bits that are not part of S_IFMT,
  making a "small" number suitable for an array index; S_IFMT_from_index does
  the reverse. These indeces can be used with the S_IFMTix_* variants; the
  others use the mode masked with S_IFMT directly.

  The _ucname and _name versions are the same, differing only in case; the
  _long_name versions provide human-readable forms suitable for logging.
 */

/* In all traditional Unix systems S_IFMT == 0xf000, so S_IFMT_scale == 0x1000
   == (1<<12); however this method will work with any other "reasonable"
   values, in particular any positive value for S_IFMT, provided
   ( 1 << S_IFMT / S_IFMT_scale ) fits inside an unsigned int without rollover - in
   general, so it spans no more than 5 bits.
*/
#define S_IFMT_scale (S_IFMT & -S_IFMT)  /* X&-X computes the greatest power of 2 that divides into X */
/* static_assert( S_IFMT > 0 && S_IFMT / S_IFMT_scale < 32 ); */

/* These need to be macros (rather than functions) to allow them to be used in
   static initialisers */
#define S_IFMT_to_index(S)   ( (S_IFMT & (S)) / S_IFMT_scale )
#define S_IFMT_from_index(I) (  S_IFMT & (I)  * S_IFMT_scale )

typedef unsigned long ifmt_set_t;

#define S_IFMT_to_set(S) (1UL << S_IFMT_to_index(S))

extern ifmt_set_t S_IFMTset_from_name(const uschar *name);      /* zero on error */
extern const uschar *S_IFMTix_to_long_name(int index);  /* NULL on error */

static inline const uschar *
S_IFMT_to_long_name(int ifmt) { /* NULL on error */
int i = S_IFMT_to_index(ifmt);
return i<0 ? NULL : S_IFMTix_to_long_name(i);
}

/* End of lf_functions.h */
