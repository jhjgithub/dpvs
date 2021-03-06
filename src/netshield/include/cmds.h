#ifndef __NS_COMMAND_H__
#define __NS_COMMAND_H__

#include <ns_task.h>

typedef void 	(*CB_TYPE0)(void);
typedef int32_t (*CB_TYPE1)(void);
typedef int32_t (*CB_TYPE2)(ns_task_t*);

#define NSCMD_IDX(x)			NSCMD_IDX_##x
#if 0
#define CMD_ITEM(n,s,r,i,c,a)  \
	[NSCMD_IDX(n)] =  {.name=__STR(n), .short_name=__STR(s), .init=i, .clean=c, .age=a, .run=r}
#else
#define CMD_ITEM(n,s,r,i,c,a)  \
	.name=__STR(n), .short_name=__STR(s), .init=i, .clean=c, .age=a, .run=r
#endif

#define append_cmd(n, c)  nscmd_append(&((n)->cmd), NSCMD_IDX(c));
#define prepend_cmd(n, c)  nscmd_prepend(&((n)->cmd), NSCMD_IDX(c));

typedef struct nscmd_module_s {
	char* 		name;
	char* 		short_name;
	CB_TYPE1	init;
	CB_TYPE0	clean;
	CB_TYPE1	age;
	CB_TYPE2	run;
} nscmd_module_t;

// command 를 추가 할때 추가 해야 함.
enum nscmd_index{
	// log should be the first because of enabling syslog
	NSCMD_IDX(log),

	NSCMD_IDX(frag4),
	NSCMD_IDX(inet),
	NSCMD_IDX(taskinfo),

	NSCMD_IDX(smgr_fast),
	NSCMD_IDX(smgr_slow),
	NSCMD_IDX(smgr_timeout),

	NSCMD_IDX(pmgr),
	NSCMD_IDX(timer),
	NSCMD_IDX(nat),
	NSCMD_IDX(arpp),

	NS_CMD_MAX
};

//////////////////////////////////////////////////////


char* 	nscmd_get_module_short_name(uint32_t id);
int32_t nscmd_init_module(void);
void 	nscmd_clean_module(void);
int32_t nscmd_append(nscmd_t* c, uint8_t cmd);
int32_t nscmd_prepend(nscmd_t* c, uint8_t cmd);
nscmd_module_t* nscmd_pop(nscmd_t* c);
void 	nscmd_setup_cmds(ns_task_t *nstask, uint8_t protocol);
int32_t nscmd_run_cmds(ns_task_t *nstask);
int32_t nscmd_register(uint32_t idx, nscmd_module_t *mod);

#endif
