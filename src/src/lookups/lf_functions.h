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
 * The st_mode field returned by stat() indicates the type of a file; these
 * functions help to interpret that.
 *
 * Usage:
 *  struct stat s;
 *  const uschar *t;
 *  stat(&s, filename);
 *  if ((t = S_IFMT_to_long_name(s.st_mode)))
 *    printf("%s is a %s\n", filename, t);
 *  else
 *    printf("%s is unknown\n", filename);
 *  if ( allowed_filetype_mask & BIT(S_IFMT_to_index(s.st_mode)) )
 *    printf("\tALLOWED\n");
 *  else
 *    printf("\tFORBIDDEN\n");
 *
 * S_IFMT_to_index shifts this to remove bits that are not part of S_IFMT,
 * making a "small" number suitable for an array index; S_IFMT_from_index does
 * the reverse. These indeces can be used with the S_IFMTix_* variants; the
 * others use the mode masked with S_IFMT directly.
 *
 * The _ucname and _name versions are the same, differing only in case; the
 * _long_name versions provide human-readable forms suitable for logging.
 *
 * Macros for use in static initialisers; take care to avoid side effects in
 * parameters
 */
#define S_IFMT_scale (S_IFMT & -S_IFMT)  /* X&-X comprises the least significant 1-bit of X, all other bits 0 */
#define S_IFMT_to_index(S)   ( (S)<0 ? -1 : (S_IFMT & (S)) / S_IFMT_scale )
#define S_IFMT_from_index(I) ( (I)<0 ? -1 :  S_IFMT & (I)  * S_IFMT_scale )

extern const uschar *S_IFMTix_to_name(int index);      /* NULL on error */
extern const uschar *S_IFMTix_to_long_name(int index); /* NULL on error */
extern const uschar *S_IFMTix_to_ucname(int index);    /* NULL on error */
extern int S_IFMTix_from_name(const uschar *name);     /* negative on error */

static inline const uschar *S_IFMT_to_name(int index)      { return S_IFMTix_to_name(     S_IFMT_to_index(index));   } /* NULL on error */
static inline const uschar *S_IFMT_to_long_name(int index) { return S_IFMTix_to_long_name(S_IFMT_to_index(index));   } /* NULL on error */
static inline const uschar *S_IFMT_to_ucname(int index)    { return S_IFMTix_to_ucname(   S_IFMT_to_index(index));   } /* NULL on error */
static inline int S_IFMT_from_name(const uschar *name)     { return S_IFMT_from_index(    S_IFMTix_from_name(name)); } /* negative on error */

/* End of lf_functions.h */
