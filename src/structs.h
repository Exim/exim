/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2006 */
/* Written by Philip Hazel. */

/* This module contains definitions of structures that are used throughout the
program. */

/* Include file stack item */

typedef struct istackstr {
  struct istackstr *prev;
  int linenumber;
  FILE *file;
  uschar filename[256];
} istackstr;

/* Flag stack item */

typedef struct flagstr {
  struct flagstr *next;
  int     length1;
  uschar *flag1;
  uschar *rep1;
  int     length2;
  uschar *flag2;
  uschar *rep2;
} flagstr;

/* Pushed string stack item */

typedef struct pushstr {
  struct pushstr *next;
  int letter;
  uschar string[1];
} pushstr;

/* Macro content and argument item */

typedef struct argstr {
  struct argstr *next;
  uschar *string;
} argstr;

/* Macro definition item */

typedef struct macrodef {
  struct macrodef *next;
  argstr *lines;
  argstr *args;
  uschar *name;
  int namelength;
} macrodef;

/* Macro execution item */

typedef struct macroexe {
  struct macroexe *prev;
  macrodef *macro;
  argstr *args;
  argstr *nextline;
} macroexe;

/* Structure for each node in a tree, used for defined entities. */

typedef struct tree_node {
  struct tree_node *left;      /* pointer to left child */
  struct tree_node *right;     /* pointer to right child */
  uschar *data;                /* pointer to the value */
  uschar  balance;             /* balancing factor */
  uschar  name[1];             /* node name - variable length */
} tree_node;

/* End of structs.h */
