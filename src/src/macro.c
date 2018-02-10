/*************************************************
*     Exim - an Internet mail transport agent    *
*************************************************/

/* Copyright (c) University of Cambridge 1995 - 2018 */
/* See the file NOTICE for conditions of use and distribution. */

/* Functions for handling macros */

#include "exim.h"

#ifdef MACRO_PREDEF
# undef store_get
# define store_get(nbytes) malloc((size_t)(nbytes))
#define string_copyn(s, len) strndup(CS(s), (len))
#endif

/*************************************************
*       Deal with an assignment to a macro       *
*************************************************/

/* We have a new definition; add to the collection.
Items are numbered so we can avoid recursion in expansions.

Args:
 name	Name of the macro.  Will be copied.
 val	Expansion result for the macro.  Will be copied.
*/

macro_item *
macro_create(const uschar * name, const uschar * val, BOOL command_line)
{
int namelen = Ustrlen(name);
macro_item * m = store_get(sizeof(macro_item) + namelen);

/* fprintf(stderr, "%s: '%s' '%s'\n", __FUNCTION__, name, val); */

m->command_line = command_line;
m->namelen = namelen;
m->replen = Ustrlen(val);
m->m_number = m_number++;
memset(&m->tnode, 0, sizeof(tree_node));
/* Use memcpy here not Ustrcpy to avoid spurious compiler-inserted check
when building with fortify-source. We know there is room for the copy into
this dummy for a variable-size array because of the way we did the memory
allocation above. */
memcpy(m->tnode.name, name, namelen+1);
m->tnode.data.ptr = string_copyn(val, m->replen);
(void) tree_insertnode(&tree_macros, &m->tnode);

return m;
}


/* Search for a macro, with an exact match on the name.
Return the node, or NULL for not-found.

Arguments:	name	key to search for
*/

macro_item *
macro_search(const uschar * name)
{
tree_node * t;

t = tree_search(tree_macros, name);
return tnode_to_mitem(t);
}


/* Search for a macro with a (possibly improper) leading substring
matching the given name.  Return the node, or NULL for not-found.

Arguments:	name	key to search on
*/

macro_item *
macro_search_prefix(const uschar * s)
{
tree_node * t;
int c;

for (t = tree_macros; t; t = c < 0 ? t->left : t->right)
  if ((c = Ustrncmp(s, t->name, tnode_to_mitem(t)->namelen)) == 0)
    return tnode_to_mitem(t);
return NULL;
}


/* Search for the macro with the largest possible leading substring
matching the given name. */

macro_item *
macro_search_largest_prefix(const uschar * s)
{
macro_item * found;
tree_node * child;
int c;

if ((found = macro_search_prefix(s)))
  {
  /* There could be a node with a larger substring also matching the
  name.  If so it must be in the right subtree; either the right child
  or (if that sorts after the name) in the left subtree of the right child. */

  child = found->tnode.right;
  while (child)
    if ((c = Ustrncmp(s, child->name, tnode_to_mitem(child)->namelen)) == 0)
      {
      found = tnode_to_mitem(child);
      child = found->tnode.right;
      }
    else if (c < 0 && (child = child->left))
      continue;
    else
      break;
  }
return found;
}



void
macro_print(uschar * name, uschar * val, void * ctx)
{
BOOL names_only = (BOOL)(long)ctx;
if (names_only)
  printf("%s\n", CS name);
else
  printf("%s=%s\n", CS name, CS val);
}



/* vi: aw ai sw=2
*/
/* End of macro.c */
