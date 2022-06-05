/*************************************************
*     xfpt - Simple ASCII->Docbook processor     *
*************************************************/

/* Copyright (c) University of Cambridge, 2006 */
/* Written by Philip Hazel. */

/* This module contains tree management routines. A tree is used for locally
defined entity values. */

#include "xfpt.h"


/***********************************************************
*          Binary Balanced Tree Management Routines        *
***********************************************************/

/* This set of routines maintains a balanced binary tree using
the algorithm given in Knuth Vol 3 page 455.

The routines make use of uschar * pointers as byte pointers,
so as to be able to do arithmetic on them, since ANSI Standard
C does not permit additions and subtractions on void pointers. */


/*************************************************
*              Flags and Parameters              *
*************************************************/

#define tree_lbal      1         /* left subtree is longer */
#define tree_rbal      2         /* right subtree is longer */
#define tree_bmask     3         /* mask for flipping bits */


/*************************************************
*         Insert a new node into a tree          *
*************************************************/

/* The node->name field must (obviously) be set, but the other
fields need not be initialized.

Arguments:
  treebase   pointer to the root of the tree
  node       the note to insert, with name field set

Returns:     TRUE if node inserted; FALSE if not (duplicate)
*/

int
tree_insertnode(tree_node **treebase, tree_node *node)
{
tree_node *p = *treebase;
tree_node **q, *r, *s, **t;
int a;

node->left = node->right = NULL;
node->balance = 0;

/* Deal with an empty tree */

if (p == NULL)
  {
  *treebase = node;
  return TRUE;
  }

/* The tree is not empty. While finding the insertion point,
q points to the pointer to p, and t points to the pointer to
the potential re-balancing point. */

q = treebase;
t = q;

/* Loop to search tree for place to insert new node */

for (;;)
  {
  int c = Ustrcmp(node->name, p->name);
  if (c == 0) return FALSE;              /* Duplicate node encountered */

  /* Deal with climbing down the tree, exiting from the loop
  when we reach a leaf. */

  q = (c > 0)? &(p->right) : &(p->left);
  p = *q;
  if (p == NULL) break;

  /* Save the address of the pointer to the last node en route
  which has a non-zero balance factor. */

  if (p->balance != 0) t = q;
  }

/* When the above loop completes, q points to the pointer to NULL;
that is the place at which the new node must be inserted. */

*q = node;

/* Set up s as the potential re-balancing point, and r as the
next node after it along the route. */

s = *t;
r = (Ustrcmp(node->name, s->name) > 0)? s->right : s->left;

/* Adjust balance factors along the route from s to node. */

p = r;

while (p != node)
  {
  if (Ustrcmp(node->name, p->name) < 0)
    {
    p->balance = tree_lbal;
    p = p->left;
    }
  else
    {
    p->balance = tree_rbal;
    p = p->right;
    }
  }

/* Now the World-Famous Balancing Act */

a = (Ustrcmp(node->name, s->name) < 0)? tree_lbal : tree_rbal;

if (s->balance == 0) s->balance = (uschar)a;        /* The tree has grown higher */
  else if (s->balance != (uschar)a) s->balance = 0; /* It's become more balanced */
else                                              /* It's got out of balance */
  {
  /* Perform a single rotation */

  if (r->balance == (uschar)a)
    {
    p = r;
    if (a == tree_rbal)
      {
      s->right = r->left;
      r->left = s;
      }
    else
      {
      s->left = r->right;
      r->right = s;
      }
    s->balance = 0;
    r->balance = 0;
    }

  /* Perform a double rotation There was an occasion when the balancing
  factors were screwed up by a bug in the code that reads a tree from
  the spool. In case this ever happens again, check for changing p to NULL
  and don't do it. It is better to have an unbalanced tree than a crash. */

  else
    {
    if (a == tree_rbal)
      {
      if (r->left == NULL) return TRUE;   /* Bail out if tree corrupt */
      p = r->left;
      r->left = p->right;
      p->right = r;
      s->right = p->left;
      p->left = s;
      }
    else
      {
      if (r->right == NULL) return TRUE;  /* Bail out if tree corrupt */
      p = r->right;
      r->right = p->left;
      p->left = r;
      s->left = p->right;
      p->right = s;
      }

    s->balance = (p->balance == (uschar)a)? (uschar)(a^tree_bmask) : 0;
    r->balance = (p->balance == (uschar)(a^tree_bmask))? (uschar)a : 0;
    p->balance = 0;
    }

  /* Finishing touch */

  *t = p;
  }

return TRUE;     /* Successful insertion */
}



/*************************************************
*          Search tree for node by name          *
*************************************************/

/*
Arguments:
  p         root of tree
  name      key to search for

Returns:    pointer to node, or NULL if not found
*/

tree_node *
tree_search(tree_node *p, uschar *name)
{
while (p != NULL)
  {
  int c = Ustrcmp(name, p->name);
  if (c == 0) return p;
  p = (c < 0)? p->left : p->right;
  }
return NULL;
}


/* End of tree.c */
