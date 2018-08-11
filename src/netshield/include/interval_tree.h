#ifndef _LINUX_INTERVAL_TREE_H
#define _LINUX_INTERVAL_TREE_H

#include <rbtree.h>
#include <stdint.h>

typedef struct rb_root rbt_root_t;

//typedef __uint128_t uint128_t;
//typedef __int128    int128_t;
typedef uint32_t 	it_value_t;
//typedef uint64_t 	it_value_t;
//typedef uint128_t it_value_t;

typedef struct interval_tree_node {
	struct rb_node rb;
	it_value_t start;
	it_value_t last;
	it_value_t __subtree_last;
	uint32_t 	idx;

} itvt_node_t;

extern void
interval_tree_insert(struct interval_tree_node *node, struct rb_root *root);

extern void
interval_tree_remove(struct interval_tree_node *node, struct rb_root *root);

extern struct interval_tree_node *
interval_tree_iter_first(struct rb_root *root, it_value_t start, it_value_t last);

extern struct interval_tree_node *
interval_tree_iter_next(struct interval_tree_node *node, it_value_t start, it_value_t last);

#endif	/* _LINUX_INTERVAL_TREE_H */
