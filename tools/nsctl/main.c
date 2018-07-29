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

//#include <rule_trace.h>
#include <hypersplit.h>
#include <rfg.h>

#include <parse_policy_json.h>

#define APPLY_FIREWALL  0x01
#define APPLY_NAT       0x02
#define SHOW_SESSION    0x04

struct arg_opts {
	char	*s_rule_file;
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
int apply_json_rule(sec_policy_t *secp, int snum, nat_policy_t *np, int nnum);
int free_policy_json(policy_json_t *p);

////////////////////////////////////////

static void print_help(void)
{
	const char *s_help =
		"NetShield Control\n"
		"\n"
		"Valid options:\n"
		"  -r, --rule FILE  specify a rule file for building\n"
		"  -f, --firewall apply firewall rule to kernel\n"
		"  -n, --nat apply nat rule to kernel\n"
		"  -s, --session show session \n"
		"\n"
		"  -h, --help  display this help and exit\n"
		"\n";

	fprintf(stdout, "%s", s_help);

	return;
}

static void parse_args(struct arg_opts *argopts, int argc, char *argv[])
{
	int option;
	const char *s_opts = "r:hfns";
	const struct option opts[] = {
		{ "rule",	  required_argument, NULL, 'r' },
		{ "firewall", no_argument,		 NULL, 'f' },
		{ "nat",	  no_argument,		 NULL, 'n' },
		{ "session",  no_argument,		 NULL, 's' },
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

		case 'f':
			argopts->flags |= APPLY_FIREWALL;
			break;

		case 'n':
			argopts->flags |= APPLY_NAT;
			break;

		case 's':
			argopts->flags |= SHOW_SESSION;
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
		get_session();
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
