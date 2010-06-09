/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2007 */
/* Written by Philip Hazel. */

/* This header defines all the global functions. */

extern void        dot_process(uschar *);
extern void        error(int, ...);
extern void        literal_process(uschar *);
extern uschar     *misc_copystring(uschar *, int);
extern void        misc_detrail(uschar *);
extern void       *misc_malloc(int);
extern uschar     *misc_readitem(uschar *, uschar *, int *, uschar *, int);
extern uschar     *misc_readstring(uschar *, int *, uschar *, int);

extern void        para_process(uschar *);

extern uschar     *read_nextline(void);
extern uschar     *read_paragraph(uschar *, int *);
extern void        read_process_macroline(uschar *, uschar *);

extern int         tree_insertnode(tree_node **, tree_node *);
extern tree_node  *tree_search(tree_node *, uschar *);

/* End of functions.h */
