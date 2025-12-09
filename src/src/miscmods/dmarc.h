/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* DMARC support.
   Copyright (c) The Exim Maintainers 2021 - 2025
   Copyright (c) Todd Lyons <tlyons@exim.org> 2012 - 2014
   License: GPL */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* Portions Copyright (c) 2012, 2013, The Trusted Domain Project;
   All rights reserved, licensed for use per LICENSE.opendmarc. */

#ifdef EXPERIMENTAL_DMARC_NATIVE
# define EXIM_HAVE_DMARC EXPERIMENTAL_DMARC_NATIVE
# define DMARC_SUPPORTS_ARC

/* from opendmarc/dmarc.h */
# define DMARC_MAXHOSTNAMELEN    256

# define DMARC_POLICY_ABSENT     14
# define DMARC_POLICY_PASS       15
# define DMARC_POLICY_REJECT     16
# define DMARC_POLICY_QUARANTINE 17
# define DMARC_POLICY_NONE       18
# define DMARC_USED_POLICY_IS_P  19
# define DMARC_USED_POLICY_IS_SP 20

# define DMARC_POLICY_SPF_ORIGIN_MAILFROM       1
# define DMARC_POLICY_SPF_ORIGIN_HELO           2

# define DMARC_POLICY_SPF_OUTCOME_NONE          0
# define DMARC_POLICY_SPF_OUTCOME_PASS          1
# define DMARC_POLICY_SPF_OUTCOME_FAIL          2
# define DMARC_POLICY_SPF_OUTCOME_TMPFAIL       3
# define DMARC_POLICY_SPF_ALIGNMENT_PASS        4
# define DMARC_POLICY_SPF_ALIGNMENT_FAIL        5

# define DMARC_POLICY_DKIM_OUTCOME_NONE         0
# define DMARC_POLICY_DKIM_OUTCOME_PASS         1
# define DMARC_POLICY_DKIM_OUTCOME_FAIL         2
# define DMARC_POLICY_DKIM_OUTCOME_TMPFAIL      3
# define DMARC_POLICY_DKIM_ALIGNMENT_PASS       4
# define DMARC_POLICY_DKIM_ALIGNMENT_FAIL       5



#elif defined(SUPPORT_DMARC)
# define EXIM_HAVE_DMARC SUPPORT_DMARC
# if DMARC_API >= 100400
#  define DMARC_SUPPORTS_ARC
# endif

# include <opendmarc/dmarc.h>
# ifdef SUPPORT_SPF
#  include <spf2/spf.h>
# endif /* SUPPORT_SPF */

#endif /* SUPPORT_DMARC */



#define DMARC_HIST_OK          1
#define DMARC_HIST_DISABLED    2
#define DMARC_HIST_EMPTY       3
#define DMARC_HIST_FILE_ERR    4
#define DMARC_HIST_WRITE_ERR   5

/* From opendmarc.c */
#define DMARC_RESULT_REJECT     0
#define DMARC_RESULT_DISCARD    1
#define DMARC_RESULT_ACCEPT     2
#define DMARC_RESULT_TEMPFAIL   3
#define DMARC_RESULT_QUARANTINE 4

/* From opendmarc-ar.h */
/* ARES_RESULT_T -- type for specifying an authentication result */
#define ARES_RESULT_UNDEFINED   (-1)
#define ARES_RESULT_PASS    0
#define ARES_RESULT_UNUSED  1
#define ARES_RESULT_SOFTFAIL    2
#define ARES_RESULT_NEUTRAL 3
#define ARES_RESULT_TEMPERROR   4
#define ARES_RESULT_PERMERROR   5
#define ARES_RESULT_NONE    6
#define ARES_RESULT_FAIL    7
#define ARES_RESULT_POLICY  8
#define ARES_RESULT_NXDOMAIN    9
#define ARES_RESULT_SIGNED  10
#define ARES_RESULT_UNKNOWN 11
#define ARES_RESULT_DISCARD 12

# define DMARC_RECORD_A_UNSPECIFIED	('\0')		/* adkim and aspf */
# define DMARC_RECORD_A_STRICT		('s')		/* adkim and aspf */
# define DMARC_RECORD_A_RELAXED		('r')		/* adkim and aspf */
# define DMARC_RECORD_P_UNSPECIFIED	('\0')		/* p and sp */
# define DMARC_RECORD_P_NONE		('n')		/* p and sp */
# define DMARC_RECORD_P_QUARANTINE	('q')		/* p and sp */
# define DMARC_RECORD_P_REJECT		('r')		/* p and sp */

#ifndef DMARC_POLICY_SPF_ALIGNMENT_PASS
/* From opendmarc/dmarc.h */
# define DMARC_POLICY_SPF_ALIGNMENT_PASS 4
# define DMARC_POLICY_SPF_ALIGNMENT_FAIL 5
#endif

#ifndef DMARC_POLICY_DKIM_ALIGNMENT_PASS
/* From opendmarc/dmarc.h */
# define DMARC_POLICY_DKIM_ALIGNMENT_PASS 4
# define DMARC_POLICY_DKIM_ALIGNMENT_FAIL 5
#endif

#define	DMARC_ARC_POLICY_RESULT_PASS	0
#define	DMARC_ARC_POLICY_RESULT_UNUSED	1
#define	DMARC_ARC_POLICY_RESULT_FAIL	2



/* These live in dmarc_common.c */
extern BOOL dmarc_abort;
extern uschar * dmarc_header_from_sender;
extern uschar * dmarc_pass_fail;
extern const misc_module_info * dmarc_dkim_mod_info;
extern const misc_module_info * dmarc_spf_mod_info;
extern int dmarc_spf_ares_result;
extern uschar ** dmarc_rua;		/* aggregate report addressees */
extern int dmarc_pct;
extern int dmarc_adkim;
extern int dmarc_aspf;
extern int dmarc_policy;
extern int dmarc_dom_policy;
extern int dmarc_subdom_policy;
extern int dmarc_spf_alignment;
extern int dmarc_dkim_alignment;
extern int dmarc_action;
extern uschar * dmarc_used_domain;
extern const uschar * dmarc_domain_policy;
extern BOOL dmarc_alignment_spf;
extern BOOL dmarc_alignment_dkim;

extern const uschar * dmarc_status;
extern const uschar * dmarc_status_text;

