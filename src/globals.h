/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2007 */
/* Written by Philip Hazel. */

/* Header file for all the global variables */


/*************************************************
*           General global variables             *
*************************************************/

extern uschar     *xfpt_share;
extern uschar     *xfpt_version;

extern tree_node  *entities;

extern flagstr    *flaglist;

extern uschar     *inbuffer;
extern istackstr  *istack;

extern int         literal_state;

extern int         nest_level;
extern int         nest_literal_stack[];
extern uschar     *next_line;

extern macroexe   *macrocurrent;
extern macrodef   *macrolist;

extern argstr     *macro_argbase;
extern argstr     *macro_starteach;

extern FILE       *outfile;

extern int         para_inline_macro;
extern uschar     *parabuffer;
extern int         popto;
extern pushstr    *pushed;

extern int         return_code;
extern uschar     *revision;

/* End of globals.h */
