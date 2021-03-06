#ifndef __POLICY_MAMAGER_H__
#define __POLICY_MAMAGER_H__

#include <sec_policy.h>
#include <hypersplit_util.h>

struct ioctl_data_s;

#define MAX_POLICY UINT_MAX

typedef struct policyset_s {
	uint8_t 		*hs_mem; 	// root memory to store policyset

	hypersplit_t 	hypersplit;
	sec_policy_t 	*spolicies;
	uint32_t 		num_spolicies;
	nat_policy_t 	*npolicies;
	uint32_t 		num_npolicies;
	uint32_t 		version;
	atomic_t 		refcnt;
} policyset_t;

enum {
	POLICYSET_FIREWALL,
	POLICYSET_NAT,

	POLICYSET_MAX
};

struct policy_manager_s {
	policyset_t *policyset[POLICYSET_MAX]; 	// 0: firewall, 1: NAT

	atomic_t 	version_cnt;
	spinlock_t 	lock;
};

typedef struct policy_manager_s pmgr_t;


#if 0
enum {
	DIM_INV		= -1,
	DIM_SIP		= 0,
	DIM_DIP		= 1,
	DIM_SPORT	= 2,
	DIM_DPORT	= 3,
	DIM_PROTO	= 4,
	DIM_MAX		= 5
};

typedef struct pktinfo_s {
	uint32_t	dims[DIM_MAX];
} pktinfo_t;
#endif


//////////////////////////////////////////////////////

int32_t pmgr_init(void);
void 	pmgr_clean(void);
int32_t pmgr_main(ns_task_t *nstask);
int32_t pmgr_apply_policy(struct ioctl_data_s *iodata);
void 	pmgr_release_policyset(policyset_t *ps);
void 	pmgr_hold_policyset(policyset_t *ps);
policyset_t* pmgr_get_policyset(int ps_type);

sec_policy_t* pmgr_get_security_policy(policyset_t *ps, uint32_t fwidx);
nat_policy_t* pmgr_get_nat_policy(policyset_t *ps, uint32_t natidx);

#endif
