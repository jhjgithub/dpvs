#ifndef __IOCTL_H__
#define __IOCTL_H__

#define OPTVAL_FLAG_NAME 	0x01
#define OPTVAL_FLAG_INDEX 	0x02
#define OPTVAL_FLAG_STRING 	0x04
#define OPTVAL_FLAG_INT 	0x08

typedef struct optval_s {
	uint32_t 	flags;
	uint32_t 	optidx;
	char 		name[32];
	union {
		uint32_t 	val;
		uint32_t 	len; 	// length for string data
	};

	char 		data[0]; 	// for string data
} optval_t;

typedef struct ioctl_data_s {
	const void 	*in;
	size_t 	insize;

	uint8_t *out;
	size_t 	outsize;
	size_t 	out_buf_len;
} ioctl_data_t;

enum {
    /* set */
	NSIOCTL_SET_MIN = 1000,

	NSIOCTL_SET_SEC_POLICY,
	NSIOCTL_SET_OPT_VALUE,

	NSIOCTL_SET_MAX,


    /* get */
	NSIOCTL_GET_MIN,

	NSIOCTL_GET_SESSION,
	NSIOCTL_GET_OPT_VALUE,
	NSIOCTL_GET_NATIP_INFO,

	NSIOCTL_GET_MAX,
};



int nsioctl_init(void);
int nsioctl_term(void);

#endif
