#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ns_typedefs.h>
#include <ioctl_policy.h>
#include <sec_policy.h>
#include <timer.h>
#include <skey.h>
#include <session.h>
#include <ioctl_session.h>
#include <nat.h>
#include <action.h>
#include <options.h>

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>

#include <parse_policy_json.h>

#include <io.h>
#include <ioctl.h>

#define APPLY_FIREWALL  0x01
#define APPLY_NAT       0x02
#define SHOW_SESSION    0x04
#define SHOW_OPT_TABLE  0x08
#define OPT_VAL  		0x10
#define SHOW_NATIP 		0x20

struct arg_opts {
	char	*s_rule_file;
	char 	*optarg;
	int		flags;
};

enum {
	IOCTL_START = 0,
	IOCTL_APPLY_FW_POLICY,
	IOCTL_DUMMY,
	IOCTL_SESSION_INFO,


	IOCTL_MAXNR
};

#define IP_FMT                  "%3u.%3u.%3u.%3u"
#if defined(__LITTLE_ENDIAN)
#define IPH(addr) \
	((unsigned char *)&addr)[3], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[0]
#elif defined(__BIG_ENDIAN)
#define IPH(addr)   IPN(addr)
#else
#error Not defined Endian Mode !
#endif

////////////////////////////////////////

int parse_policy_json(policy_json_t *p, char *fname);
int get_session(void);
int get_option_table(void);
int get_option_value(int);
int apply_json_rule(sec_policy_t *secp, int snum, nat_policy_t *np, int nnum);
int free_policy_json(policy_json_t *p);

////////////////////////////////////////

static void print_help(void)
{
	const char *s_help =
		"NetShield Control\n"
		"\n"
		"Valid options:\n"
		"  -r, --rule FILE,  specify a rule file for building\n"
		"  -f, --firewall apply firewall rule to kernel\n"
		"  -n, --nat apply nat rule to kernel\n"
		"  -i, --natip show natip\n"
		"  -s, --session show session \n"
		"  -t, --table show option table \n"
		"  -o, --opt NAME[=VALUE], get/set option value \n"
		"\n"
		"  -h, --help  display this help and exit\n"
		"\n";

	fprintf(stdout, "%s", s_help);

	return;
}

static void parse_args(struct arg_opts *argopts, int argc, char *argv[])
{
	int option;
	const char *s_opts = "r:o:hfnsti";
	const struct option opts[] = {
		{ "rule",	  required_argument, NULL, 'r' },
		{ "firewall", no_argument,		 NULL, 'f' },
		{ "nat",	  no_argument,		 NULL, 'n' },
		{ "natip",	  no_argument,		 NULL, 'i' },
		{ "session",  no_argument,		 NULL, 's' },
		{ "table",     no_argument,		 NULL, 't' },
		{ "opt",      required_argument, NULL, 'o' },
		{ "help",	  no_argument,		 NULL, 'h' },
		{ NULL,		  0,				 NULL, 0   }
	};

	assert(argopts && argv);

	if (argc < 2) {
		print_help();
		return;
	}

	while ((option = getopt_long(argc, argv, s_opts, opts, NULL)) != -1) {
		switch (option) {
		case 'r':
			if (access(optarg, F_OK) == -1) {
				perror(optarg);
				return;
			}

			argopts->s_rule_file = optarg;
			break;

		case 'o':
			argopts->flags |= OPT_VAL;
			argopts->optarg = optarg;
			break;

		case 'f':
			argopts->flags |= APPLY_FIREWALL;
			break;

		case 'n':
			argopts->flags |= APPLY_NAT;
			break;

		case 'i':
			argopts->flags |= SHOW_NATIP;
			break;

		case 's':
			argopts->flags |= SHOW_SESSION;
			break;

		case 't':
			argopts->flags |= SHOW_OPT_TABLE;
			break;

		case 'h':
			print_help();
			exit(0);

		default:
			print_help();
			return;
		}
	}
}

////////////////////////////////////////////////

int main(int argc, char *argv[])
{
	struct arg_opts argopts = {
		.s_rule_file	= NULL,
		.flags			= 0,
	};

	printf("\n=========================\n");
	printf("Start Processing Packet Classification Rules \n");

	parse_args(&argopts, argc, argv);

	if (argopts.flags & SHOW_SESSION) {

		nsctl_get_session();

#if 0
		int rc;
		int val=0;
		rc = nsctl_get_option_int(OPT_IDX(bl_btime), &val);
		printf("1. rc=%d, val=%d \n", rc, val);

		rc = nsctl_set_option_int(OPT_IDX(bl_btime), val+100);
		val = 0;
		rc = nsctl_get_option_int(OPT_IDX(bl_btime), &val);
		printf("2. rc=%d, val=%d \n", rc, val);
#endif
	}
	else if (argopts.flags & SHOW_OPT_TABLE) {
		char *buf;
		int rc;
		size_t len;

		rc = nsctl_get_option_table(&buf, &len);
		if (rc == 0 && buf) {
			printf("%s \n", buf);
			free(buf);
		}
	}
	else if (argopts.flags & OPT_VAL) {
		char *p = strchr(argopts.optarg, '=');
		int rc;
		int val=0;

		if (p == NULL) {
			rc = nsctl_get_option_int_by_name(argopts.optarg, &val);
			if (rc == 0) {
				printf("val=%d \n", val);
			}
		}
		else {
			int32_t v;

			*p = '\0';
			p++;

			v = atoi(p);

			rc = nsctl_set_option_int_by_name(argopts.optarg, v);
		}
	}
	else if (argopts.flags & SHOW_NATIP) {
		char *buf;
		int rc;
		size_t len;

		rc = nsctl_get_sting_data(NSIOCTL_GET_NATIP_INFO, &buf, &len);
		if (rc == 0 && buf) {
			printf("%s \n", buf);
			free(buf);
		}
	}

	if (argopts.s_rule_file != NULL) {
		policy_json_t p;
		memset(&p, 0, sizeof(policy_json_t));

		parse_policy_json(&p, argopts.s_rule_file);
		if (p.sec_policy[0]) {
			if (argopts.flags & APPLY_FIREWALL) {
				apply_json_rule(p.sec_policy[0], p.num_sec_policy[0], NULL, 0);
			}
		}

		if (p.sec_policy[1]) {
			if (argopts.flags & APPLY_NAT) {
				apply_json_rule(p.sec_policy[1], p.num_sec_policy[1], p.nat_policy, p.num_nat_policy);
			}
		}

		free_policy_json(&p);
	}

	return 0;
}
