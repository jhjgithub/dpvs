#include <stdio.h>
#include <stdint.h>
#include "dpdk.h"
#include <ipv4.h>

#include <ns_typedefs.h>
#include <macros.h>
#include <cmds.h>
#include <ns_dbg.h>
#include <session.h>
#include <smgr.h>
#include <pmgr.h>
#include <options.h>
#include <log.h>


//////////////////////////////////////////////////////

struct dpvs_timer g_ns_timer;

DECLARE_DBG_LEVEL(2);

//////////////////////////////////////////////////////


//////////////////////////////////////////////////////
static nscmd_module_t *nscmd_module_list[NS_CMD_MAX] = { NULL, };

/* -------------------------------- */
/*         Code 영역                */
/* -------------------------------- */

int32_t nscmd_register(uint32_t idx, nscmd_module_t *mod)
{
	if (idx >= NS_CMD_MAX || mod == NULL) {
		return -1;
	}

	nscmd_module_list[idx] = mod;
	//printf("Register: %s \n", mod->name);

	return 0;
}

nscmd_module_t* nscmd_get_module(uint32_t idx)
{
	if (idx >= NS_CMD_MAX) {
		return NULL;
	}

	return nscmd_module_list[idx];
}

int32_t nscmd_append(nscmd_t *c, uint8_t cmd)
{
	int8_t next = (c->tail + 1) % MAX_CMDS;

	if (c->head == next) {
		ns_err("The NetShield cmd stack is overflowed. head=%d, tail=%d", c->head, c->tail);
		return -1;
	}

	c->tail = next;
	c->stack[c->tail] = cmd;

	return 0;
}

int32_t nscmd_prepend(nscmd_t *c, uint8_t cmd)
{
	int8_t prev = (c->head - 1) % MAX_CMDS;

	if (c->tail == prev) {
		ns_err("The NetShield cmd stack is underflowed. head=%d, tail=%d", c->head, c->tail);
		return -1;
	}

	// pop시에는 head를 증가한 다음 데이터를 가져가므로
	// 현재의 head 포인터는 old 포인터이다.
	// 그러므로 현재 포인터에 넣고 head를 감소해야 한다.
	c->stack[c->head] = cmd;
	c->head = prev;

	return 0;
}

nscmd_module_t* nscmd_pop(nscmd_t *c)
{
	uint8_t cmd;

	if (c->head == c->tail) {
		dbg(4, "The NetShield cmd stack is empty. head=%d, tail=%d", c->head, c->tail);
		return NULL;
	}

	c->head = (c->head + 1) % MAX_CMDS;
	cmd = c->stack[c->head];

	return nscmd_get_module(cmd);
}

////////////////////////////////////

int nscmd_callback_timer(void* arg)
{
	uint32_t i;
	uint32_t t;
	nscmd_module_t *c;

	// 기준 시간을 증가 한다.
	t = nstimer_inc_time();

	for (i = 0; i < NS_CMD_MAX; i++) {
		c = nscmd_get_module(i);
		if (c == NULL || c->age == NULL) {
			continue;
		}

		c->age();
	}

	// run on every minute
	if (t > 60 && (t % 60) == 0) {
	}

    struct timeval tv;

    tv.tv_sec = GET_OPT_VALUE(age_interval);
    tv.tv_usec = 0;
	dpvs_timer_update(&g_ns_timer, &tv, true);

	return DTIMER_OK;
}

char* nscmd_get_module_short_name(uint32_t id)
{
	nscmd_module_t *c  = nscmd_get_module(id);

	if (c == NULL) {
		return NULL;
	}

	return c->short_name;
}

int32_t nscmd_run_cmds(ns_task_t *nstask)
{
	int32_t ret = NS_ACCEPT;
	nscmd_module_t *cmd = NULL;
	session_t *ses;

	ENT_FUNC(3);

	while ((cmd = nscmd_pop(&nstask->cmd)) != NULL) {
		dbg(7, "Run module: %s", cmd->name);

		if (cmd->run == NULL) {
			continue;
		}

		ret = cmd->run(nstask);

		if (ret == NS_ACCEPT) {
			continue;
		}
		else if (ret == NS_STOLEN) {
			dbg(5, "Stolen by : %s", cmd->name);
			break;
		}
		else if (ret == NS_DROP || ret == NS_DEL_SESSION) {
			dbg(5, "Droped by : %s", cmd->name);
			break;
		}
		else if (ret == NS_STOP) {
			dbg(5, "Stop by : %s", cmd->name);
			break;
		}
		else if (ret == NS_REPEAT) {
			dbg(5, "Repeat by : %s", cmd->name);
			break;
		}
		else {
			dbg(0, "Unknown result : module=%s, ret=%d", cmd->name, ret);
			break;
		}
	}

	// and then, finalize packet
	if (ret == NS_STOLEN || ret == NS_STOP) {
		return ret;
	}

	ses = nstask->ses;

#if 0
	// ACCEPT/DROP 모두 통계 생성
	if (GET_OPT_VALUE(wst)) {
		wst_main(nstask, ret);
	}
#endif

	if (likely(nstask->ses != NULL)) {
		session_release(nstask->ses);
		nstask->ses = NULL;
	}

	if (nstask->mp_fw.policy_set) {
		//pmgr_release_policyset(nstask->mp_fw.policy_set);
	}

	if (nstask->mp_nat.policy_set) {
		//pmgr_release_policyset(nstask->mp_nat.policy_set);
	}

	if (ret == NS_DEL_SESSION) {
		if (ses) {
			smgr_delete_session(ses, 0);
		}

		ret = NS_DROP;
	}

	return ret;
}

void nscmd_setup_common_cmds(ns_task_t *nstask)
{
	// fragmentation, call frag_main()
	//append_cmd(nstask, frag);

#if 0
	if (GET_OPT_VALUE(bl)) {
		// blacklist
		// call bl_main()
		wcq_push_cmd(&nstask->cmd, NS_CMD_IDX(bl));
	}
#endif

	// call parse_inet_protocol()
	append_cmd(nstask, inet);

	// call init_task_info()
	append_cmd(nstask, taskinfo);

#if 0
	// anomaly in IPS
	if (GET_OPT_VALUE(ips) && GET_OPT_VALUE(panomaly)) {
		// call panomaly_main()
		append_cmd(nstask, panomaly);
	}
#endif

	// call smgr_fast_main()
	append_cmd(nstask, smgr_fast);
}

void nscmd_setup_cmds(ns_task_t *nstask, uint8_t protocol)
{
	switch (protocol) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	default:
		nscmd_setup_common_cmds(nstask);
		break;

	case IPPROTO_AH:
	case IPPROTO_ESP:
#if 0
		// fragmentation, call frag_main()
		append_cmd(nstask, frag);
		// call init_inet_protocol()
		wcq_push_cmd(&nstask->cmd, NS_CMD_IDX(inet));
		append_cmd(nstask, inet);
		// call ipsec_input_main()
		append_cmd(nstask, iipsec);
#endif
		break;

	case IPPROTO_IPIP:
		break;
	}
}

int32_t nscmd_init_module(void)
{
	uint32_t i;
	nscmd_module_t *c;

	// 1. 각 컴퍼넌트 초기화
	// 모든 모듈의 초기화는 여기서 수행 한다.

	for (i = 0; i < NS_CMD_MAX; i++) {
		c = nscmd_get_module(i);
		if (c == NULL || c->init == NULL) {
			continue;
		}

		if (c->init()) {
			return -1;
		}
	}

	// 2. timer 등록
    struct timeval tv;

    tv.tv_sec =  GET_OPT_VALUE(age_interval);
    tv.tv_usec = 0;

    i = dpvs_timer_sched(&g_ns_timer, &tv, nscmd_callback_timer, NULL, true);
    //i = dpvs_timer_sched_period(&g_ns_timer, &tv, nscmd_callback_timer, NULL, true);
    if (i != EDPVS_OK) {
		ns_err("Cannot register timer");
	}

	return 0;
}

void nscmd_clean_module(void)
{
	int32_t i;
	nscmd_module_t *c;

	// 2. timer 제거
	dpvs_timer_reset(&g_ns_timer, true);

	// 3. 각 컴퍼넌트 제거
	for (i = NS_CMD_MAX - 1; i >= 0; i--) {
		c = nscmd_get_module(i);
		if (!c->clean) {
			continue;
		}

		c->clean();
	}
}
