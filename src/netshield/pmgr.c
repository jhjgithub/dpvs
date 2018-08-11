#include <stdio.h>
#include <stdint.h>
#include <dpdk.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <session.h>
//#include <smgr.h>
//#include <action.h>
#include <pmgr.h>
//#include <options.h>
#include <cmds.h>
#include <ioctl_policy.h>
#include <arp_proxy.h>
#include <utils.h>
#include <ioctl.h>



//////////////////////////////////////////////////////
// Policy Manager

pmgr_t g_pmgr;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////
uint32_t hypersplit_load(policyset_t *ps, uint8_t *data);
void 	hypersplit_free(hypersplit_t *hs);
void 	pmgr_free_policyset(policyset_t *ps);
int32_t pmgr_commit_new_policy(policyset_t *ps, int32_t nat);
void    pmgr_update_nat_arp(policyset_t *ps);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */


void pmgr_hold_policyset(policyset_t *ps)
{
	if (ps) {
		atomic_inc(&ps->refcnt);
	}
}

void pmgr_release_policyset(policyset_t *ps)
{
	int32_t ref;

	if (!ps) {
		return;
	}

	ref = atomic_dec_return(&ps->refcnt);

	if (ref > 0) {
		return;
	}
	else if (ref < 0) {
		ns_log("Something wrong with policyset: %p", ps);
		return;
	}

	pmgr_free_policyset(ps);
}

void pmgr_free_policyset(policyset_t *ps)
{
	if (!ps) {
		return;
	}

	dbg(3, "Free policyset: 0x%p", ps);

#if 0
	if (ps->hypersplit.trees) {
		hypersplit_free(&ps->hypersplit);
	}
#endif

	if (ps->hs_mem) {
		ns_free_v(ps->hs_mem);
	}

	if (ps->spolicies) {
		ns_free_v(ps->spolicies);
	}

	if (ps->npolicies) {
		ns_free_v(ps->npolicies);
	}

	ns_free(ps);
}

#if 0
policyset_t* pmgr_get_new_policyset(void)
{
	policyset_t *ps = NULL;

	ns_rw_lock(&g_pmgr.lock) {
		ps = g_pmgr.policyset[1];

		if (ps == NULL) {
			ps = ns_malloc_kz(sizeof(policyset_t));
			g_pmgr.policyset[1] = ps;

			dbg(3, "Alloc new policyset: 0x%p", ps);
			pmgr_hold_policyset(ps);
		}

	} ns_rw_unlock(&g_pmgr.lock);

	pmgr_hold_policyset(ps);

	return ps;
}
#endif

policyset_t* pmgr_get_policyset(int32_t idx)
{
	policyset_t *ps = NULL;

	ns_rd_lock_irq() {
		//ps = (policyset_t*)rcu_dereference(g_pmgr.policyset[idx]);
		ps = g_pmgr.policyset[idx];
		if (ps) {
			if (atomic_read(&ps->refcnt) > 0) {
				atomic_inc(&ps->refcnt);
			}
			else {
				// refcnt가 1 보다 작다면 해제중인 객체이다.
				ps = NULL;
				ns_err("Someone tried to access wrond memory");
			}
		}

	} ns_rd_unlock_irq();

	return ps;
}

#if 0
policyset_t* pmgr_get_firewall_policyset(void)
{
	return pmgr_get_policyset(0);
}

policyset_t* pmgr_get_nat_policyset(void)
{
	return pmgr_get_policyset(1);
}
#endif

uint32_t pmgr_load_security_policy(policyset_t *ps, uint32_t num_policy, uint8_t *data)
{
	uint32_t l = 0, nl;
	sec_policy_t *secp = NULL, *f;

	l = num_policy * sizeof(sec_policy_t);

	secp = ns_malloc_v(l);
	ns_mem_assert(secp, "sec_policy", return 0);

	// to make sure all the page assigned
	memset(secp, 0, l);
	memcpy(secp, data, l);
	ps->num_spolicies = num_policy;
	ps->spolicies = secp;

	dbg(5, "Security Policy Info");
	dbg(5, "Num of Policies: %d", ps->num_spolicies);
	dbg(5, "Num of Mem: %d", l);

	return l;
}

uint32_t pmgr_load_nat_policy(policyset_t *ps, uint32_t num_policy, uint8_t *data)
{
	uint32_t l = 0, nl;
	nat_policy_t *natp, *p;

	l = num_policy * sizeof(nat_policy_t);

	natp = ns_malloc_v(l);
	ns_mem_assert(natp, "nat_policy", return 0);

	// to make sure all the page assigned
	memset(natp, 0, l);

	memcpy(natp, data, l);
	ps->num_npolicies = num_policy;
	ps->npolicies = natp;

	for (int i=0; i<num_policy; i++) {
		p = &natp[i];

		// init internal data
		ns_init_lock(&p->nat_lock);
		p->ip_cnt = -1;
		p->available_ip = NULL;
		INIT_LIST_HEAD(&p->ip_list);
	}

	dbg(5, "NAT Policy Info");
	dbg(5, "Num of Policies: %d", ps->num_npolicies);
	dbg(5, "Num of Mem: %d", l);

	return l;
}

int32_t pmgr_apply_policy(struct ioctl_data_s *iodata)
{
	int32_t ret = 0;
	uint32_t l,t;
	policyset_t *ps = NULL;
	ioctl_policyset_t *ioctl_ps;
	uint8_t *data;
	ioctl_ps = (ioctl_policyset_t*)iodata->in;

	ps = ns_malloc_kz(sizeof(policyset_t));

	if (ps == NULL) {
		return -ENOMEM;
	}

	pmgr_hold_policyset(ps);

	data = (uint8_t*)ioctl_ps->data;

	l = hypersplit_load(ps, data);
	if (l == 0 || l != ioctl_ps->sz_hs) {
		ret = -EINVAL;
		goto END;
	}
	data += ioctl_ps->sz_hs;

	t = sizeof(sec_policy_t) * ioctl_ps->num_fw_policy;
	l = pmgr_load_security_policy(ps, ioctl_ps->num_fw_policy, data);
	if (l == 0 || l != t) {
		ret = -EINVAL;
		goto END;
	}
	data += t;

	if (ioctl_ps->num_nat_policy) {
		t = sizeof(nat_policy_t) * ioctl_ps->num_nat_policy;
		l = pmgr_load_nat_policy(ps, ioctl_ps->num_nat_policy, data);
		if (l == 0 || l != t) {
			ret = -EINVAL;
			goto END;
		}
	}

	ret = pmgr_commit_new_policy(ps, ioctl_ps->num_nat_policy);

END:
	if (ret != 0) {
		dbg(3, "Cancel new policyset: 0x%p", ps);
		pmgr_release_policyset(ps);
	}

	return ret;
}

// 룰이 적용 된후 NAT arp proxy IP에 대해서 처리 한다.
void pmgr_update_nat_arp(policyset_t *ps)
{
	int32_t i,rcnt;
	int32_t j;
	nat_policy_t* natp;
	ip4_t sip, eip;
	sec_policy_t *new_rule;
	uint8_t iface_idx = IFACE_IDX_MAX;
	uint16_t flag;

	ENT_FUNC(3);

	// clean it up
	arpp_clean_ip();

	new_rule = ps->spolicies;
	rcnt = ps->num_spolicies;

	dbg(4, "NAT rule count: %d", rcnt);

	for (i=0; i<rcnt; i++) {
		if (!(new_rule[i].action & ACT_NAT))
			continue;

		for (j=0; j<2; j++) {
			uint32_t npid = new_rule[i].nat_policy_id[j];
			sip = eip = 0;
			flag = 0;

			//natp = new_rule[i].nat_policy[j];
			natp = pmgr_get_nat_policy(ps, npid);
			if (natp == NULL) {
				continue; 
			}

#if 0
			if ((natp->flags & NATF_DYNAMIC_IP) && 
				!g_enable_nic_notify) {
				g_enable_nic_notify = 1;
			}
#endif
			if (!(natp->flags & NATF_ARP_PROXY)) {
				continue;
			}

			dbg(6, "fwr=%p, id=%d, nat[%d]=%p, id=%d", 
				&new_rule[i], new_rule[i].rule_id, i, natp, natp?natp->id:-1);

			if (natp->flags & NATF_SNAT_MASK) {
				// INFO: 다이나믹 할당이면 arp proxy가 동작 안해도 된다.
				if (natp->flags & NATF_DYNAMIC_IP) {
					continue;
				}

				sip = natp->nip[0];
				eip = natp->nip[1];

				// NAT NIC를 지정하지 않은 경우에 NAT IP를 이용해서 자동 생성 한다.
				if (natp->iface_idx == IFACE_IDX_MAX) {
					natp->iface_idx = ns_get_nic_idx_by_ip(htonl(natp->nip[0]));
				}

				iface_idx = natp->iface_idx;

				// if end ip is MASK value, make end ip
				if (natp->flags & NATF_SNAT_MASKING) {
					eip = sip | ~eip;
					// masking을 하면 eip 주소가 네트웍 주소가 된다.
					// 그러므로 1을 감소해서 호스트 주소 영역으로 만든다.
					ns_dec_ip(&eip);
				}

				flag |= ARP_PRXY_SNAT;
			}
			else if (natp->flags & NATF_DNAT_MASK) {
				// DNAT인 경우 목적지 IP에 대해서 arp proxying 한다
				sip = new_rule[i].range.dst.min;
				eip = new_rule[i].range.dst.max;

				// NAT NIC를 지정하지 않은 경우에 NAT IP를 이용해서 자동 생성 한다.
				if (new_rule[i].range.nic.min == IFACE_IDX_MAX) {
					new_rule[i].range.nic.min = ns_get_nic_idx_by_ip(htonl(sip));
				}

				iface_idx = new_rule[i].range.nic.min;
				flag |= ARP_PRXY_DNAT;
			}
			else {
				dbg(0, "Unexpected condition");
				continue;
			}

			dbg(6, "sip:" IP_FMT ", eip:" IP_FMT , IPH(sip), IPH(eip));

			if (sip == 0 && eip == 0) {
				continue;
			}
			else if (eip == 0) {
				eip = sip;
			}

			arpp_add_ip(iface_idx, sip, eip, flag);
			dbg(5, "NAT arp proxy: iface_idx: %u, sip:" IP_FMT ",eip:" IP_FMT , 
				natp->iface_idx, IPH(sip), IPH(eip));
		}
	}
}

int32_t pmgr_commit_new_policy(policyset_t *ps, int32_t nat)
{
	policyset_t *old = NULL;

	nat = !!nat;

	// change new memory
	ns_rd_lock_irq() {

#if 0
		old = (policyset_t*)rcu_dereference(g_pmgr.policyset[nat]);
		rcu_assign_pointer(g_pmgr.policyset[nat], ps);
#else
		old = g_pmgr.policyset[nat];
		g_pmgr.policyset[nat] = ps;
#endif
		if (ps) {
			ps->version = atomic_inc_return(&g_pmgr.version_cnt);
			pmgr_hold_policyset(ps);
		}

	} ns_rd_unlock_irq();

	if (nat) {
		pmgr_update_nat_arp(ps);
	}

	if (old) {
		pmgr_release_policyset(old);
	}

	dbg(0, "Commit New Policy: %p, ver=%u, nat=%d", ps, ps->version, nat);

	return 0;
}

sec_policy_t* pmgr_get_security_policy(policyset_t *ps, uint32_t fwidx)
{
	if (fwidx >= ps->num_spolicies) {
		dbg(5, "out of fw range: fwidx=%u, num_spolicies=%u", fwidx, ps->num_spolicies);
		return NULL;
	}

#if 0
	if (index != ps->policy[index].rule_idx) {
		return NULL;
	}
#endif

	return &ps->spolicies[fwidx];
}

nat_policy_t* pmgr_get_nat_policy(policyset_t *ps, uint32_t natidx)
{
	if (natidx >= ps->num_npolicies) {
		dbg(5, "out of nat range: natidx=%u, num_npolicies=%u", natidx, ps->num_npolicies);
		return NULL;
	}

	return &ps->npolicies[natidx];
}

int32_t pmgr_init(void)
{

	return 0;
}

void pmgr_clean(void)
{
	int32_t i;

	for (i=0; i<POLICYSET_MAX; i++) {
		if (g_pmgr.policyset[i]) {
			pmgr_release_policyset(g_pmgr.policyset[i]);
		}

		g_pmgr.policyset[i] = NULL;
	}
}

int32_t pmgr_main(ns_task_t *nstask)
{
	policyset_t* fps = NULL, *nps = NULL;
	pktinfo_t pi;
	int32_t ret = NS_DROP;
	uint32_t midx;
	mpolicy_t *mp;

	ENT_FUNC(3);

	//bzero(&pi, sizeof(pi));
	bzero(&nstask->mp_fw, sizeof(nstask->mp_fw));
	mp = &nstask->mp_fw;

	pi.dims[DIM_SIP]   = (uint32_t)nstask->skey.src;
	pi.dims[DIM_DIP]   = (uint32_t)nstask->skey.dst;
	pi.dims[DIM_SPORT] = (uint16_t)nstask->skey.sp;
	pi.dims[DIM_DPORT] = (uint16_t)nstask->skey.dp;
	pi.dims[DIM_PROTO] = (uint8_t)nstask->skey.proto;
	pi.dims[DIM_NIC]   = nstask->skey.inic;

	// for Firewall
	fps = pmgr_get_policyset(POLICYSET_FIREWALL);
	if (!fps) {
		dbg(0, "No Firewall Policy !");
		return NS_DROP;
	}

	midx = hypersplit_search(&fps->hypersplit, &pi);
	if (midx == HS_NO_RULE) {
		// matched default rule
		dbg(0, "No Matched Firewall Rule");
		goto ERR;
	}
	else if ((mp->policy = pmgr_get_security_policy(fps, midx)) == NULL) {
		goto ERR;
	}
	else if (!(mp->policy->action & ACT_ALLOW)) {
		goto ERR;
	}

	dbg(4, "Matched Firewall Rule ID: %u" , midx);

	mp->policy_set = fps;

	// call smgr_slow_main()
	append_cmd(nstask, smgr_slow);

	// for NAT
	mp = &nstask->mp_nat;
	bzero(&nstask->mp_nat, sizeof(nstask->mp_nat));
	nps = pmgr_get_policyset(POLICYSET_NAT);
	if (nps) {
		midx = hypersplit_search(&nps->hypersplit, &pi);
		if (midx != HS_NO_RULE &&
			((mp->policy = pmgr_get_security_policy(nps, midx)) != NULL)) {

			dbg(4, "Matched NAT Rule ID: %u" , midx);
			mp->policy_set = nps;
		}
		else {
			mp->policy = NULL;
			pmgr_release_policyset(nps);
		}
	}

	return NS_ACCEPT;

ERR:
	if (fps) {
		pmgr_release_policyset(fps);
	}

	if (nps) {
		pmgr_release_policyset(nps);
	}

	return ret;
}

