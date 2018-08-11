#include <stdio.h>
#include <stdint.h>
#include <dpdk.h>
#include <ipv4.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <session.h>
#include <pmgr.h>

/* Hypersplit Packet Classification */

DECLARE_DBG_LEVEL(6);

/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

void hypersplit_free(hypersplit_t *hs)
{
#if 0
	int32_t i;

	if (hs == NULL || hs->trees) {
		return;
	}

	for (i = 0; i < hs->tree_num; i++) {
		struct hs_tree *t = &hs->trees[i];

		if (t->root_node) {
			ns_free_v(t->root_node);
		}
	}

	ns_free(hs->trees);
#endif
}

uint32_t hypersplit_get_memory_size(hypersplit_t *hypersplit, uint32_t *total_node)
{
	size_t tmem = 0;
	uint32_t nodes = 0;
	int32_t j;

	if (!hypersplit || !hypersplit->trees) {
		return 0;
	}


	tmem += (sizeof(struct hs_tree) * hypersplit->tree_num);

	for (j = 0; j < hypersplit->tree_num; j++) {
		struct hs_tree *t = &hypersplit->trees[j];

		tmem += (t->inode_num * sizeof(struct hs_node));
		nodes += t->inode_num;
	}

	if (total_node) {
		*total_node = nodes;
	}

	return tmem;
}

uint32_t hypersplit_load(policyset_t *ps, uint8_t *hsmem)
{
	uint32_t l = 0;
	int32_t ret = -1;
	int32_t j, tmem = 0, tnode = 0;
	hypersplit_t *hs = &ps->hypersplit;
	uint8_t *p = hsmem;

	if (hs == NULL) {
		return 0;
	}

	memset(hs, 0, sizeof(hypersplit_t));

	DBG(0, "Loading Hypersplit...");

	memcpy(&hs->tree_num, hsmem, sizeof(int32_t));
	hsmem += sizeof(int32_t);

	memcpy(&hs->def_rule, hsmem, sizeof(int32_t));
	hsmem += sizeof(int32_t);

	l = sizeof(struct hs_tree) * hs->tree_num;

	DBG(0, "Num Tree: %d", hs->tree_num);
	DBG(0, "Def Rule: %d", hs->def_rule);
	DBG(0, "Tree Mem Len: %u ", l);

	hs->trees = ns_malloc_k(l);
	if (hs->trees == NULL) {
		return 0;
	}

	for (j = 0; j < hs->tree_num; j++) {
		struct hs_tree *t = &hs->trees[j];
		int32_t mlen=0;

		memset(t, 0, sizeof(struct hs_tree));

		memcpy(&t->inode_num, hsmem, sizeof(int32_t));
		hsmem += sizeof(int32_t);

		memcpy(&t->depth_max, hsmem, sizeof(int32_t));
		hsmem += sizeof(int32_t);

		memcpy(&mlen, hsmem, sizeof(int32_t));
		hsmem += sizeof(int32_t);

		t->enode_num = t->inode_num + 1;

		tnode += t->inode_num;
		tmem += mlen;

		if ((t->inode_num * sizeof(struct hs_node)) != mlen) {
			DBG(5, "something wrong: expected=%lu, mlen=%d \n", 
				t->inode_num * sizeof(struct hs_node), mlen);
			goto ERROR;
		}

		t->root_node = ns_malloc_v(mlen);
		if (t->root_node == NULL) {
			goto ERROR;
		}

		memcpy(t->root_node, hsmem, mlen);
		hsmem += mlen;

		DBG(0, "#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d",
			j + 1, t->inode_num, mlen, t->depth_max);
	}


	DBG(0, "Total: Node=%d, Mem=%d", tnode, tmem);

	return (hsmem - p);

ERROR:

	if (hs->trees) {
		for (j = 0; j < hs->tree_num; j++) {
			struct hs_tree *t = &hs->trees[j];

			if (t->root_node) {
				ns_free_v(t->root_node);
			}
		}

		ns_free(hs->trees);
	}

	return 0;
}

uint32_t hypersplit_search(hypersplit_t *hs, pktinfo_t *pkt)
{
	uint32_t i, pri;
	uint32_t id, offset;
	const struct hs_node *node, *root_node;

	if (hs == NULL) {
		return HS_NO_RULE;
	}

	offset = hs->def_rule + 1;
	pri = hs->def_rule;

	for (i = 0; i < hs->tree_num; i++) {
		id = offset;
		root_node = hs->trees[i].root_node;

		do {
			node = root_node + id - offset;

			if (pkt->dims[node->dim] <= node->threshold) {
				id = node->lchild;
			}
			else {
				id = node->rchild;
			}

		} while (id >= offset);

		if (id < pri) {
			pri = id;
		}
	}

	if (pri == hs->def_rule) {
		return HS_NO_RULE;
	}

	return pri;
}
