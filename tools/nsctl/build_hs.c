#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#include <stdint.h>
//#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
//#include <inttypes.h>
//#include <sys/types.h>
//#include <sys/stat.h>
#include <fcntl.h>
//#include <sys/ioctl.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>

#include <ns_typedefs.h>
#include <ioctl_policy.h>
#include <sec_policy.h>
//#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>
//#include <nat.h>
#include <action.h>

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>

#include <parse_policy_json.h>
#include <io.h>

int send_to_daemon(sec_policy_t *fwp, int num, const char *hsfile, nat_policy_t *np, int nnum);

///////////////////////////////////////////////

void save_hypersplit(hypersplit_t *hypersplit, const char *filename)
{
	int fd;

	if (filename == NULL) {
		return;
	}

	fd = open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0644);

	if (fd == -1) {
		printf("cannot open hs.bin \n");
		return;
	}

	ssize_t l = 0;

	l = write(fd, &hypersplit->tree_num, sizeof(uint32_t));
	l = write(fd, &hypersplit->def_rule, sizeof(uint32_t));

	if (l == 0) {
	}

	printf("Saving Hypersplit... \n");
	printf("Num Tree: %u \n", hypersplit->tree_num);
	printf("Def Rule: %u \n", hypersplit->def_rule);

	int j, tmem = 0, tnode = 0;

	for (j = 0; j < hypersplit->tree_num; j++) {
		struct hs_tree *t = &hypersplit->trees[j];
		int mlen = t->inode_num * sizeof(struct hs_node);

		tmem += mlen;
		tnode += t->inode_num;

		printf("#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d \n",
			   j + 1, t->inode_num, mlen, t->depth_max);

		l = write(fd, &t->inode_num, sizeof(int));
		l = write(fd, &t->depth_max, sizeof(int));
		l = write(fd, &mlen, sizeof(int));
		l = write(fd, (void *)t->root_node, mlen);
	}

	close(fd);

	printf("Total: Node=%d, Mem=%d \n", tnode, tmem);
}

void* load_hypersplit(const char *filename)
{
	int fd;
	struct hypersplit_s *hs;
	ssize_t l = 0;

	l = sizeof(struct hypersplit_s);
	hs = malloc(l);

	if (hs == NULL) {
		return NULL;
	}

	memset(hs, 0, l);

	fd = open(filename, O_RDONLY);

	if (fd == -1) {
		printf("cannot open hs.bin \n");
		return NULL;
	}

	read(fd, &hs->tree_num, sizeof(int));
	read(fd, &hs->def_rule, sizeof(int));

	printf("Loading Hypersplit \n");
	printf("Num Tree: %d \n", hs->tree_num);
	printf("Def Rule: %d \n", hs->def_rule);

	hs->trees = malloc(sizeof(struct hs_tree) * hs->tree_num);

	int j, tmem = 0, tnode = 0;

	for (j = 0; j < hs->tree_num; j++) {
		struct hs_tree *t = &hs->trees[j];
		int mlen;

		read(fd, &t->inode_num, sizeof(int));
		t->enode_num = t->inode_num + 1;

		read(fd, &t->depth_max, sizeof(int));
		read(fd, &mlen, sizeof(int));

		tnode += t->inode_num;
		tmem += mlen;

		if ((t->inode_num * sizeof(struct hs_node)) != mlen) {
			printf("something wrong: mlen=%d \n", mlen);
		}

		t->root_node = malloc(mlen);

		read(fd, (void *)t->root_node, mlen);

		printf("#%d Tree: Node=%-5d, Mem=%-7d Bytes, Maxdepth=%d \n",
			   j + 1, t->inode_num, mlen, t->depth_max);
	}

	close(fd);

	printf("Total: Node=%d, Mem=%d \n", tnode, tmem);

	return hs;
}

////////////////////////////////////////////////

int convert_ruleset(struct rule_set *p_rs, sec_policy_t *secp, int num)
{
	int i;
	struct rule *rules, *r;
	sec_policy_t *f;

	rules = calloc(num, sizeof(struct rule));

	if (rules == NULL) {
		return -1;
	}

	for (i = 0; i < num; i++) {
		r = &rules[i];
		f = &secp[i];

		r->pri = i;
		r->dims[DIM_SIP][0] = f->range.src.min;
		r->dims[DIM_SIP][1] = f->range.src.max;

		r->dims[DIM_DIP][0] = f->range.dst.min;
		r->dims[DIM_DIP][1] = f->range.dst.max;

		r->dims[DIM_SPORT][0] = f->range.sp.min;
		r->dims[DIM_SPORT][1] = f->range.sp.max;

		r->dims[DIM_DPORT][0] = f->range.dp.min;
		r->dims[DIM_DPORT][1] = f->range.dp.max;

		r->dims[DIM_PROTO][0] = f->range.proto.min;
		r->dims[DIM_PROTO][1] = f->range.proto.max;

		r->dims[DIM_NIC][0] = f->range.nic.min;
		r->dims[DIM_NIC][1] = f->range.nic.max;
#if 0
		printf("sip: %u->%u\n", r->dims[DIM_SIP][0], r->dims[DIM_SIP][1]);
		printf("dip: %u->%u\n", r->dims[DIM_DIP][0], r->dims[DIM_DIP][1]);
		printf("sp: %u->%u\n", r->dims[DIM_SPORT][0], r->dims[DIM_SPORT][1]);
		printf("dp: %u->%u\n", r->dims[DIM_DPORT][0], r->dims[DIM_DPORT][1]);
		printf("proto: %u->%u\n", r->dims[DIM_PROTO][0], r->dims[DIM_PROTO][1]);
		printf("nic: %u->%u\n", r->dims[DIM_NIC][0], r->dims[DIM_NIC][1]);
#endif
	}

	p_rs->rules = rules;
	p_rs->rule_num = num;
	p_rs->def_rule = num - 1;

	//printf("Num Rules: %d \n", num);

	return 0;
}

int apply_json_rule(sec_policy_t *secp, int snum, nat_policy_t *np, int nnum)
{
	struct partition pa, pa_grp;
	hypersplit_t hypersplit;

	printf("Build Hypersplit: %s \n", nnum ? "NAT" : "Firewall");
	fflush(NULL);

	/*
	 * Loading classifier
	 */
	pa.subsets = calloc(1, sizeof(*pa.subsets));
	if (!pa.subsets) {
		printf("Cannot allocate memory for subsets\n");
		return -1;
	}

	convert_ruleset(pa.subsets, secp, snum);

	pa.subset_num = 1;
	pa.rule_num = pa.subsets[0].rule_num;

	// grouping
	printf("Grouping ... \n");
	fflush(NULL);

	if (pa.rule_num > 2) {
		if (rf_group(&pa_grp, &pa)) {
			printf("Error Grouping ... \n");
			return -1;
		}

		unload_partition(&pa);

		pa.subset_num = pa_grp.subset_num;
		pa.rule_num = pa_grp.rule_num;
		pa.subsets = pa_grp.subsets;

		pa_grp.subset_num = 0;
		pa_grp.rule_num = 0;
		pa_grp.subsets = NULL;
		unload_partition(&pa_grp);

		printf("subset_num=%d, rule=%d \n", pa.subset_num, pa.rule_num);
		fflush(NULL);
	}

	/*
	 * Building
	 */
	printf("Building ...\n");
	fflush(NULL);

	if (hs_build(&hypersplit, &pa)) {
		printf("Building fail\n");
		fflush(NULL);
		return -1;
	}

	printf("Building pass\n");
	fflush(NULL);

	const char *f = "/tmp/hs.bin";
	save_hypersplit(&hypersplit, f);
	//load_hypersplit(f);
	nsctl_send_to_daemon(secp, snum, f, np, nnum);

	unlink(f);
	unload_partition(&pa);
	hs_destroy(&hypersplit);

	return 0;
}
