#include <stdio.h>
#include <stdint.h>
#include <dpdk.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <ns_malloc.h>
#include <ns_task.h>
#include <ns_dbg.h>
#include <session.h>
#include <smgr.h>
#include <action.h>
#include <pmgr.h>
#include <options.h>
#include <cmds.h>
#include <ioctl_session.h>
#include <tcp_state.h>
#include <ioctl.h>
#include <log.h>


//////////////////////////////////////////////////////

smgr_t		*g_smgr; 

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////

//void netshield_create_sem_cache(int32_t size);
int32_t smgr_post_main(ns_task_t *nstask);
int32_t nstimer_get_lifetime(uint32_t cur_time, uint32_t timeout, uint32_t timestamp);


/* -------------------------------- */
/*        Code 영역                 */
/* -------------------------------- */

uint32_t smgr_get_next_sid(void)
{
	return (uint32_t)atomic_inc_return(&g_smgr->last_id);
}

uint32_t smgr_get_session_count(void)
{
	return atomic_read(&g_smgr->all);
}

void smgr_remove_alist(smgr_t *smgr, session_t *ses)
{
	if (smgr == NULL) {
		return;
	}

	atomic_dec(&smgr->all);
	atomic_dec(&smgr->mine);

	ns_rw_lock_irq(&smgr->smgr_lock) {
		list_del(&ses->alist);
		session_release(ses);

#if 0
		if (!list_empty(&ses->rlist)) {
			list_del(&ses->rlist);
			session_release(ses);
		}
#endif

	} ns_rw_unlock_irq(&smgr->smgr_lock);
}

void smgr_add_alist(smgr_t *smgr, session_t* ses)
{
	if (smgr == NULL) {
		return;
	}

	atomic_inc(&smgr->all);
	atomic_inc(&smgr->mine);

	ns_rw_lock_irq(&smgr->smgr_lock) {
		list_add_tail(&ses->alist, &g_smgr->all_slist);
		session_hold(ses);

	} ns_rw_unlock_irq(&smgr->smgr_lock);
}

int32_t smgr_add_session(smgr_t *smgr, session_t *ses)
{
	ENT_FUNC(3);

	smgr_add_alist(smgr, ses);

	session_insert(smgr->stab, ses);
	nstimer_insert(&ses->timer, 10);

	dbg(5, "Add a new session: ses=%p, refcnt=%d", ses, atomic_read(&ses->refcnt));

	return 0;
}

int32_t smgr_delete_session(session_t *ses, uint32_t flags)
{
	ENT_FUNC(3);

	dbg(5, "Delete old session: ses=0x%p, refcnt=%d", ses, atomic_read(&ses->refcnt));

	if (flags & SMGR_DEL_SAVE_LOG) {
		// 세션 종료시 INFO 로그도 같이 남김 (통계에서 사용)
		if (ses->action & ACT_LOG_INFO) {
			nslog_session(ses, NSLOG_STAT_INFO);
		}

		if (ses->action & ACT_LOG_CLOSE) {
			nslog_session(ses, NSLOG_STAT_CLOSE);
		}
	}

	smgr_remove_alist(g_smgr, ses);

	session_remove(g_smgr->stab, ses);
	nstimer_remove(&ses->timer);

	return 0;
}

int32_t smgr_delete_by_ip(ip_t ip, int32_t kind)
{
	session_t *ses = NULL, *n;
	ip_t	*cmp_ip;
	int32_t del_cnt = 0;

START:
	ns_rw_lock_irq(&g_smgr->smgr_lock) {

		list_for_each_entry_safe(ses, n, &g_smgr->all_slist, alist) {

			switch (kind) {
			default:
			case SMGR_DEL_SKEY_SRC:
				cmp_ip = &ses->skey.src;
				break;

			case SMGR_DEL_SKEY_DST:
				cmp_ip = &ses->skey.dst;
				break;

			case SMGR_DEL_SNAT:
				cmp_ip = &ses->natinfo.ip[0];
				break;

			case SMGR_DEL_DNAT:
				cmp_ip = &ses->natinfo.ip[1];
				break;

			}

			if (ip == *cmp_ip) {
				del_cnt++;
				// 지울 세션은 6초(DSYNC를 위한 5초 + 1)후 삭제 된다.
				// DSYNC가 동작하는 경우 싱크가 이루어져서 삭제 된다.
				//lft_change_timeout(&ses->lft, 6);

				// 그러나 패킷이 계속 들어 오는 경우 세션이 계속 살아 있게 된다.
				// 그래서 바로 지워야 한다.
				// unlock없이 호출하면 deadlock이다.
				ns_rw_unlock_irq(&g_smgr->smgr_lock);
				smgr_delete_session(ses, 0);
				goto START;
			}
		}

	} ns_rw_unlock_irq(&g_smgr->smgr_lock);

	return del_cnt;
}

int32_t smgr_show_session_info(ioctl_data_t *iodata)
{
	int32_t ret=0;
	ioctl_get_sess_t *user_sinfo;
	ioctl_session_t *is;
	uint32_t scnt, max_cnt, len, idx;
	session_t *ses, *n;
	ioctl_get_sess_t *in = (ioctl_get_sess_t*)iodata->in;

	ENT_FUNC(3);

	max_cnt = smgr_get_session_count();
	if (max_cnt == 0) {
		iodata->out = NULL;
		iodata->outsize = 0;
		return 0;
	}

	if (in->num_sess != 0 && in->num_sess < max_cnt) {
		max_cnt = in->num_sess;
	}

	len = sizeof(ioctl_get_sess_t) + (sizeof(ioctl_session_t) * max_cnt);

	dbg(5, "Current session: %u, memlen=%u", max_cnt, len);
	user_sinfo = rte_malloc(NULL, len, 1);
	if (user_sinfo == NULL) {
		return -1;
	}

	scnt = 0;
	idx = 0;
	is = (ioctl_session_t*)user_sinfo->data;

	list_for_each_entry_safe(ses, n, &g_smgr->all_slist, alist) {
		if (idx < in->start_idx) {
			idx ++;
			continue;
		}

		ioctl_session_t *s = &is[idx];
		uint32_t ctime = nstimer_get_time();

		skey_t *dsk = &s->skey;
		skey_t *ssk = &ses->skey;

		dsk->src = ssk->src;
		dsk->dst = ssk->dst;
		dsk->sp = ssk->sp;
		dsk->dp = ssk->dp;
		dsk->proto = ssk->proto;

		s->sid = ses->sid;
		s->born_time = ses->born_time;
		s->timeout = nstimer_get_lifetime(ctime, ses->timer.timeout, ses->timer.timestamp);

		s->fwpolicy_id = ses->mp_fw.policy ? ses->mp_fw.policy->rule_id : 0;

		scnt ++;
		idx ++;

		if (scnt >= max_cnt) {
			break;
		}
	}

	user_sinfo->num_sess = scnt;
	iodata->out = (void*)user_sinfo;
	iodata->outsize = sizeof(ioctl_get_sess_t) + (sizeof(ioctl_session_t) * scnt);

	return 0;
}

session_t *smgr_get_ftpdata_parent(session_t *ses)
{
	if (ses->tcpst.pftpparent != NULL &&
		!(ses->action & ACT_PRXY_FTP)) {

		return (session_t *)ses->tcpst.pftpparent;
	}

	return NULL;
}

void smgr_set_ftpdata_parent(session_t *ses, session_t *parent)
{
#if 0
	if (ses) {
		if (parent) {
			session_hold(parent);
		}

		ses->tcpst.pftpparent = (void *)parent;
	}
#endif
}

int32_t smgr_slow_main(ns_task_t *nstask)
{
	smgr_t *smgr = g_smgr;
	session_t *ses = NULL;
	sec_policy_t *fwp=NULL, *natp=NULL;
	policyset_t  *fwps=NULL, *natps = NULL;
	int32_t ret = NS_DROP;

	ENT_FUNC(3);

	// for Firewall
	fwps = pmgr_get_policyset(POLICYSET_FIREWALL);
	fwp = nstask->mp_fw.policy;
	if (fwps != nstask->mp_fw.policy_set) {

		if (fwps) {
			pmgr_release_policyset(fwps);
		}

		return NS_DROP;
	}

	dbg(5, "Firewall Rule Info: desc=%s, action=0x%lx", fwp->desc, fwp->action);

	natp = nstask->mp_nat.policy;
	if (natp) {
		natps = pmgr_get_policyset(POLICYSET_NAT);
		if (natps != nstask->mp_nat.policy_set) {
			if (natps) {
				pmgr_release_policyset(natps);
			}

			natp = NULL;
			natps = NULL;
		}
		else {
			dbg(5, "NAT Rule Info: desc=%s, action=0x%lx", natp->desc, natp->action);
		}
	}

	ses = session_alloc();
	if (ses == NULL) {
		dbg(2, "Cannot alloc a new session");
		goto ERR;
	}

	memcpy(&ses->skey, &nstask->skey, sizeof(skey_t));

	ses->sid = smgr_get_next_sid();
	ses->born_time = nstimer_get_time();
	//ses->timeout = policy->timeout;
	ses->timeout = -1; 	// to use system default value
	ses->action = fwp->action;
	ses->action = ACT_ALLOW | ACT_LOG_CREATE | ACT_LOG_CLOSE;

	memcpy(&ses->mp_fw, &nstask->mp_fw, sizeof(mpolicy_t));
	// XXX: no need to increase refcnt because nstask already had
	//pmgr_policyset_hold(fwps);

	if (natp) {
		if (nat_bind_info(ses, &nstask->mp_nat, nstask->skey.inic)) {
			goto ERR;
		}

		ses->action |= natp->action;
		memcpy(&ses->mp_nat, &nstask->mp_nat, sizeof(mpolicy_t));
		// XXX: no need to increase refcnt because nstask already had
		//pmgr_policyset_hold(natps);
	}

	smgr_add_session(smgr, ses);

	nstask->ses = ses;
	session_hold(ses);

	// 최초에 만들어진 세션은 정방향 처리 한다.
	nstask->flags |= TASK_FLAG_DIR_CS;

	// 새로운 세션 이다.
	nstask->flags |= TASK_FLAG_NEW_SESS;

	if (nstask->skey.proto == IPPROTO_TCP) {
		tcp_init_seq(nstask);
	}

	smgr_post_main(nstask);

	ret = NS_ACCEPT;

	return ret;

ERR:
	if (fwps) {
		pmgr_release_policyset(fwps);
	}

	if (natps) {
		pmgr_release_policyset(natps);
	}

	if (ses) {
		session_free(ses);
	}

	return NS_DROP;
}

int32_t smgr_timeout(ns_task_t *nstask)
{
	iph_t		*iph;
	int32_t		timeout = 0, parent_timeout=0, state_changed = 0, tm_change = 0;
	session_t 	*ses, *parent = NULL;
	int			oldst1=0, oldst2=0;

	ENT_FUNC(3);

	iph = ns_get_ip_hdr(nstask);
	ses = nstask->ses;
	if (unlikely(ses == NULL)) {
		return NS_ACCEPT;
	}

	switch (iph->next_proto_id) {
	case IPPROTO_UDP:
		if (ses->timeout != -1) {
			timeout = ses->timeout;
		}
		else {
			// UDP에서 응답 패킷이 있는 경우 양방향 통신으로 보고
			// 응답이 완료 되었으므로 타임아웃을 줄인다.
			timeout = IS_DIR_CS(nstask) ? GET_OPT_VALUE(timeout_udp) : GET_OPT_VALUE(timeout_udp_reply);
		}

		break;

	case IPPROTO_TCP:
		timeout = GET_OPT_VALUE(timeout_close); 	// 10 sec
		parent = smgr_get_ftpdata_parent(ses);

		// TCP seq를 검사한다.
		if (tcp_track_seq(nstask) && GET_OPT_VALUE(drop_tcp_oow)) {
			// drop out of window packet
			dbg(0, "tcp stateful inspection error !");

			return NS_DROP;
		}

		oldst1 = ses->tcpst.tseq[0].state;
		oldst2 = ses->tcpst.tseq[1].state;

		state_changed = tcp_track_states(nstask, &timeout);
		// the session came from Magic, so send DSYNC Update
		//state_changed |= MAKE_BIT(nstask->flags & WTF_MAGIC_SESS);

		if (timeout == -1) {
			timeout = GET_OPT_VALUE(timeout_tcp);
		}

		dbg(5, "Update TCP session: SID=%u, timeout=%d, state=%d:%d -> %d:%d, tcp_changed=%d",
			ses->sid,
			timeout,
			oldst1, oldst2,
			ses->tcpst.tseq[0].state,
			ses->tcpst.tseq[1].state, state_changed);

		break;

	case IPPROTO_ICMP:
		state_changed = 1;

		if (IS_DIR_CS(nstask)) {
			timeout = ses->timeout == -1 ? GET_OPT_VALUE(timeout_icmp) : ses->timeout;
		}
		else {
			timeout = GET_OPT_VALUE(timeout_icmp_reply);
		}

		break;

	default:
		timeout = ses->timeout == -1 ? GET_OPT_VALUE(timeout_unknown) : ses->timeout;
	}

	tm_change = nstimer_change_timeout(&ses->timer, timeout);

	// ftpdata has to update its control session
	if (parent && tm_change) {
		parent_timeout = ses->timeout == -1 ? GET_OPT_VALUE(timeout_tcp) : ses->timeout;
		nstimer_change_timeout(&parent->timer, parent_timeout);
	}

	return NS_ACCEPT;
}

int32_t smgr_init(void)
{
	smgr_t *smgr = NULL;

	ENT_FUNC(3);

	dbg(3, "Init Session Manager");

	smgr = (smgr_t *)ns_malloc_kz(sizeof(smgr_t));
	ns_mem_assert(smgr, "session manager", return -1);

	smgr->stab = session_init();
	if (smgr->stab == NULL) {
		ns_free(smgr);
		smgr = NULL;
		ns_err("Can't initialize Session Table");

		return -1;
	}

	ns_init_lock(&smgr->smgr_lock);
	INIT_LIST_HEAD(&smgr->all_slist);

	g_smgr = smgr;

	return 0;
}

void smgr_clean(void)
{
	void *stab;
	session_t *ses, *n;

	ENT_FUNC(3);

	dbg(3, "Clean Session Manager");

	list_for_each_entry_safe(ses, n, &g_smgr->all_slist, alist) {
		smgr_delete_session(ses, 0);
	}

	stab = g_smgr->stab;

	session_clean(stab);

	ns_free(g_smgr);
}

int32_t smgr_fast_main(ns_task_t *nstask)
{
	int32_t ret;

	ENT_FUNC(3);

	ret = NS_ACCEPT;

	nstask->skey.hashkey = session_make_hash(&nstask->skey);

	DBGKEY(0, "TASK_KEY", &nstask->skey);

	nstask->ses = session_search(g_smgr->stab, &nstask->skey);

	if (nstask->ses == NULL) {
		dbg(0, "-----+ Begin Slow Path +-----");
		// call pmgr_main()
		append_cmd(nstask, pmgr);
	}
	else {
		dbg(0, "++++++ Begin Fast Path ++++++");

		if (!(nstask->skey.flags & SKF_REVERSE_MATCHED)) {
			nstask->flags |= TASK_FLAG_DIR_CS;
		}

		smgr_post_main(nstask);
	}

	return ret;
}

int32_t smgr_post_main(ns_task_t *nstask)
{
	skb_t *skb;
	session_t *ses = nstask->ses;

	ENT_FUNC(3);

	skb = ns_get_skb(nstask);

	// call smgr_timeout()
	append_cmd(nstask, smgr_timeout);

	if (ses->action & ACT_NAT) {
		// call nat_main()
		append_cmd(nstask, nat);
	}

	if (ses->action & ACT_LOG_CREATE) {
		nslog_session(ses, NSLOG_STAT_OPEN);
		ses->action &= ~ACT_LOG_CREATE;
	}

	ses->pktcnt[DIR_IDX(nstask)].packets ++;
	ses->pktcnt[DIR_IDX(nstask)].bytes += skb->pkt_len;

	return NS_ACCEPT;
}


///////////////////////

static nscmd_module_t mod_smgr[] = {
	[0] = {CMD_ITEM(smgr_timeout, SMGR_TIMEOUT, smgr_timeout, NULL, NULL, NULL)},
	[1] = {CMD_ITEM(smgr_fast,  SMGR_FAST, smgr_fast_main, smgr_init, smgr_clean, NULL)},
	[2] = {CMD_ITEM(smgr_slow, SMGR_SLOW, smgr_slow_main, NULL, NULL, NULL)},
};

static void __attribute__ ((constructor)) smgr_register(void)
{
	nscmd_register(NSCMD_IDX(smgr_timeout), &mod_smgr[0]);
	nscmd_register(NSCMD_IDX(smgr_fast), &mod_smgr[1]);
	nscmd_register(NSCMD_IDX(smgr_slow), &mod_smgr[2]);
}

