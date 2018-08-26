#ifndef __NLS_H
#define __NLS_H

#include <options.h>

typedef struct _nls_msg {
	char*		group;
	char*		val_list;
	char* 		msg;
} nls_msg_t;

#define NLS_ID(x)				NLS_ID_##x
#define NLS_OPT_ITEM(i,g,d,m)	[OPT_IDX(i)]={.msg=__STR(m), .group=__STR(g), .val_list=__STR(d)}
#define NLS_ITEM(i,m)			[NLS_ID(i)]={.msg=__STR(m)}

enum {
	// Option table NLS MSG
	// 0 ~ OPT_MAX 까지는 option table과 ID를 공유 한다.

	NLS_OPT_END = OPT_MAX,

	// 일반 NLS MSG
	NLS_ID_START,
	NLS_ID(nls_test),



	NLS_ID_MAX

};


/* -------------------------------- */
/*         Prototype 선언 영역      */
/* -------------------------------- */
/* extern 함수는 doxygen에서 제외   */
///@cond DOXGEN_EXCLUDE_THIS


char* nls_get_msg(uint32_t id);
char* nls_get_group(uint32_t id);
char* nls_get_value_list(uint32_t id);

///@endcond

#endif
