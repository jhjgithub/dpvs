#ifndef __PARSE_JSON_H__
#define __PARSE_JSON_H__

typedef struct policy_json_s {
	void 	*sec_policy[2]; 	// 0: firewall, 1: nat
	int 	num_sec_policy[2];
	void 	*nat_policy;
	int 	num_nat_policy;
} policy_json_t;



#endif
