#ifndef __IOCTL_H__
#define __IOCTL_H__

enum {
    /* set */
	NSIOCTL_SET_MIN = 1000,

	NSIOCTL_SET_SEC_POLICY,

	NSIOCTL_SET_MAX,


    /* get */
	NSIOCTL_GET_MIN,

	NSIOCTL_GET_SESSION,

	NSIOCTL_GET_MAX,
};



int nsioctl_init(void);
int nsioctl_term(void);

#endif
