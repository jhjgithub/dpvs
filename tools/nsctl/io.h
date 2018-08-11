#ifndef __NSCTL_IO_H__
#define __NSCTL_IO_H__

int nsctl_send_to_daemon(sec_policy_t *secp, int num, const char *hsfile, nat_policy_t *np, int nnum);
int nsctl_get_option_int(uint32_t optidx, int *value);
int nsctl_get_option_string(uint32_t optidx, char **buf, size_t *len);
int nsctl_get_option_table(char **buf, size_t *len);
int nsctl_set_option_int(uint32_t optidx, int value);
int nsctl_get_option_int_by_name(char *name, int *value);
int nsctl_set_option_int_by_name(char *name, int value);
int nsctl_get_session(void);
int nsctl_get_iface_idx(char *iface_name, int *value);
int nsctl_get_sting_data(int cmd, char **buf, size_t *len);



#endif
