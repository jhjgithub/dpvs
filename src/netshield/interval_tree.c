#include <stdlib.h>
#include <stddef.h>
#include <interval_tree.h>
#include <interval_tree_generic.h>
#include <interval_tree.h>

#define START(node) ((node)->start)
#define LAST(node)  ((node)->last)

#if 0
INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     unsigned long, __subtree_last,
		     START, LAST,, interval_tree)
#else
INTERVAL_TREE_DEFINE(struct interval_tree_node, rb,
		     it_value_t, __subtree_last,
		     START, LAST,, interval_tree)
#endif


// 0: no match
// n: matched lowest ID + 1
uint32_t interval_tree_search(it_value_t query, struct rb_root *root)
{
	struct interval_tree_node *node;
	uint32_t idx = 0;

	for (node = interval_tree_iter_first(root, query, query); 
		 node;
		 node = interval_tree_iter_next(node, query, query)) {

		if (node->idx < idx) {
			idx = node->idx;
		}
	}

	return idx;
}

