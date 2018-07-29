#ifndef __IOCTL_POLICY_H__
#define __IOCTL_POLICY_H__


typedef struct ioctl_policyset_s {
	uint32_t 	sz_hs;
	uint32_t 	num_fw_policy;
	uint32_t 	num_nat_policy;
	char 		data[0];

} ioctl_policyset_t;


#endif
