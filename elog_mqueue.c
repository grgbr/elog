#include "common.h"
#include <utils/signal.h>
#include <utils/string.h>
#include <utils/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <sys/syslog.h>

/*
 * Default permissions assigned to message queue at creation time.
 */
#define DFLT_MODE  (0600)

/*
 * Set a small amount so that unpriviledged processes may mq_open() without
 * hitting default system limits.
 * See /proc/sys/fs/mqueue/msg_max section in mq_overview(7) man page.
 */
#define DFLT_DEPTH (10U)

#define show_error(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

static int __elog_nonull(1, 2)
parse_mode(const char * __restrict arg, mode_t * __restrict mode)
{
	elog_assert(arg);
	elog_assert(mode);

	if (upath_parse_mode(arg, mode) ||
	    (*mode &
	     ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH))) {
		show_error("invalid mode '%s' specified.\n", arg);
		return -EINVAL;
	}

	return 0;
}

static int __elog_nonull(1, 2)
parse_depth(const char * __restrict arg, unsigned int * __restrict depth)
{
	elog_assert(arg);
	elog_assert(depth);

	int          err;
	const char * msg;

	err = ustr_parse_uint_range(arg, depth, 1, UMQ_MSG_MAX_NR);
	if (!err)
		return 0;

	switch (err) {
	case -EINVAL:
		msg = "integer format expected";
		break;

	case -ERANGE:
		msg = "out of range integer";
		break;

	default:
		elog_assert(0);
	}

	show_error("invalid depth '%s' specified: %s.\n", arg, msg);

	return -EINVAL;
}

static char                  buff[ELOG_LINE_MAX];
static volatile sig_atomic_t stop;

static void
handle_term(int signo __unused)
{
	stop = 1;
}

static void
setup_sigs(void)
{
	struct sigaction          term_act = {
		.sa_handler = handle_term,
		.sa_flags   = 0
	};
	const struct usig_new_act sig_acts[] = {
		{ .no = SIGHUP,  .act = &term_act },
		{ .no = SIGINT,  .act = &term_act },
		{ .no = SIGQUIT, .act = &term_act },
		{ .no = SIGTERM, .act = &term_act }
	};
	unsigned int              s;

	term_act.sa_mask = *usig_empty_msk;
	for (s = 0; s < stroll_array_nr(sig_acts); s++)
		usig_addset(&term_act.sa_mask, sig_acts[s].no);

	usig_setup_actions(sig_acts, NULL, stroll_array_nr(sig_acts));
}

#if defined(CONFIG_ELOG_DEBUG)

static void
close_mqueue(mqd_t mqd)
{
	elog_assert(mqd >= 0);

	umq_close(mqd);
}

#else  /* !defined(CONFIG_ELOG_DEBUG) */

static inline void
close_mqueue(mqd_t mqd __unused)
{
	elog_assert(mqd >= 0);
}

#endif /* defined(CONFIG_ELOG_DEBUG) */

static bool __elog_nonull(1)
is_mqueue_name_valid(const char * __restrict name)
{
	elog_assert(name);

	int err;

	err = umq_validate_name(name);
	if (err < 0) {
		show_error("invalid logging message queue name '%s': "
		           "%s (%d).\n",
		           name,
		           strerror(-err),
		           -err);
		return false;
	}

	return true;
}

static int __elog_nonull(1)
create_mqueue(const char * __restrict name, unsigned int depth, mode_t mode)
{
	elog_assert(name);
	elog_assert(depth);
	elog_assert(!(mode & ~(S_IRUSR | S_IWUSR |
	                       S_IRGRP | S_IWGRP |
	                       S_IROTH | S_IWOTH)));

	mqd_t          mqd;
	mode_t         msk;
	struct mq_attr attr = {
		.mq_maxmsg  = depth,
		.mq_msgsize = sizeof(buff)
	};

	if (!is_mqueue_name_valid(name))
		return EXIT_FAILURE;

	msk = umask(~mode);
	mqd = umq_new(name,
	              O_RDONLY | O_EXCL | O_CLOEXEC | O_NONBLOCK,
	              DEFFILEMODE,
	              &attr);
	umask(msk);

	if (mqd < 0) {
		show_error("cannot create logging message queue '%s': "
		           "%s (%d).\n",
		           name,
		           strerror(-mqd),
		           -mqd);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int __elog_nonull(1)
destroy_mqueue(const char * __restrict name)
{
	elog_assert(name);

	int err;

	if (!is_mqueue_name_valid(name))
		return EXIT_FAILURE;

	err = umq_unlink(name);
	if (err && (err != -ENOENT)) {
		show_error("cannot unlink logging message queue: %s (%d).\n",
		           strerror(-err),
		           -err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static int __elog_nonull(1)
open_mqueue(const char * __restrict name, int flags)
{
	elog_assert(name);

	mqd_t          mqd;
	struct mq_attr attr;

	if (!is_mqueue_name_valid(name))
		return -EINVAL;

	mqd = umq_open(name, O_RDONLY | flags);
	if (mqd < 0) {
		show_error("cannot open logging message queue '%s': %s (%d).\n",
		           name,
		           strerror(-mqd),
		           -mqd);
		return mqd;
	}

	umq_getattr(mqd, &attr);
	if (attr.mq_msgsize != sizeof(buff)) {
		show_error("unexpected logger queue line size (%ld).\n",
		           attr.mq_msgsize);
		goto close;
	}

	return mqd;

close:
	close_mqueue(mqd);

	return -EINVAL;
}

static int __elog_nonull(1)
print_msg(struct elog_mqueue_head * __restrict msg, size_t size)
{
	elog_assert(msg);

	ssize_t blen;

	blen = elog_parse_mqueue_msg(msg, size);
	if (blen < 0)
		return blen;

	printf("[%10ld.%06ld] %.*s[%d]: {%8s|%-6s} %.*s\n",
	       msg->tstamp.tv_sec,
	       msg->tstamp.tv_nsec / 1000U,
	       msg->body,
	       &msg->data[0],
	       msg->pid,
	       elog_get_facility_label(msg->prio),
	       elog_get_severity_label(msg->prio),
	       (int)blen,
	       &msg->data[msg->body]);

	return 0;
}

static int __elog_nonull(1)
drain_mqueue(const char * __restrict name, bool follow)
{
	elog_assert(name);

	mqd_t mqd;

	mqd = open_mqueue(name, follow ? 0 : O_NONBLOCK);
	if (mqd < 0)
		return EXIT_FAILURE;

	setup_sigs();

	setlinebuf(stdout);

	while (!stop) {
		ssize_t sz;

		sz = umq_recv(mqd, buff, sizeof(buff), NULL);
		if (sz > 0) {
			if (print_msg((struct elog_mqueue_head *)buff, sz))
				show_error("skipping invalid message !\n");
		}
		else if (sz == -EAGAIN)
			stop = 1;
		else if (!sz)
			show_error("skipping empty line !\n");
		else
			elog_assert(sz == -EINTR);
	}

	fflush_unlocked(stdout);

	close_mqueue(mqd);

	return EXIT_SUCCESS;
}

static int __elog_nonull(1)
flush_mqueue(const char * __restrict name)
{
	elog_assert(name);

	mqd_t mqd;

	mqd = open_mqueue(name, O_NONBLOCK);
	if (mqd < 0)
		return EXIT_FAILURE;

	setup_sigs();

	while (!stop) {
		ssize_t sz;

		sz = umq_recv(mqd, buff, sizeof(buff), NULL);
		if (sz >= 0)
			continue;
		else if (sz == -EAGAIN)
			stop = 1;
		else
			elog_assert(sz == -EINTR);
	}

	close_mqueue(mqd);

	return EXIT_SUCCESS;
}

#define USAGE \
"Usage:\n" \
"       %1$s drain [<DRAIN_OPTION>] <NAME>\n" \
"       Extract and print logging message queue content to standard output.\n" \
"\n" \
"       %1$s flush <NAME>\n" \
"       Clear logging message queue content.\n" \
"\n" \
"       %1$s create [<CREATE_OPTIONS>] <NAME>\n" \
"       Create logging message queue.\n" \
"\n" \
"       %1$s destroy <NAME>\n" \
"       Destroy logging message queue.\n" \
"\n" \
"       %1$s [-h|--help] [help]\n" \
"       This help message.\n" \
"\n" \
"With DRAIN_OPTION:\n" \
"    -f|--follow -- output messages continuously as queue grows.\n" \
"\n" \
"With CREATE_OPTIONS:\n" \
"    -d|--depth <DEPTH> -- setup logging queue with a maximum number\n" \
"                          of DEPTH messages (defaults to `%2$u').\n" \
"    -m|--mode <MODE>   -- create logging queue with MODE permission bits set\n" \
"                          (defaults to `%3$o').\n" \
"\n" \
"Where:\n" \
"    NAME  -- POSIX message queue name, including the leading `/',\n" \
"             [2:255] bytes long string.\n" \
"    MODE  -- message queue creation permission bits, octal integer with\n" \
"             eXecute bits rejected.\n" \
"    DEPTH -- maximum number of messages the queue may hold, integer [1:].\n"

static void __elog_nonull(1)
show_usage(FILE * stdio)
{
	elog_assert(stdio);

	fprintf(stdio,
	        USAGE,
	        program_invocation_short_name,
	        DFLT_DEPTH,
	        DFLT_MODE);
}

int
main(int argc, char * const argv[])
{
	enum {
		DRAIN_CMD,
		FLUSH_CMD,
		CREATE_CMD,
		DESTROY_CMD,
		HELP_CMD,
		INVAL_CMD
	}              cmd = HELP_CMD;
	int            ret = EXIT_FAILURE;
	bool           follow = false;
	unsigned int   depth = DFLT_DEPTH;
	mode_t         mode = DFLT_MODE;

	while (true) {
		int                        oind;
		int                        ochr;
		static const struct option opts[] = {
			{ "follow", no_argument,       NULL, 'f' },
			{ "depth",  required_argument, NULL, 'd' },
			{ "mode",   required_argument, NULL, 'm' },
			{ "help",   no_argument,       NULL, 'h' },
			{ NULL,     0,                 NULL,  0 }
		};

		ochr = getopt_long(argc, argv, ":fd:m:h", opts, &oind);
		if (ochr < 0)
			/* End of command line option parsing. */
			break;

		switch (ochr) {
		case 'f':
			follow = true;
			break;

		case 'd':
			if (parse_depth(optarg, &depth))
				return EXIT_FAILURE;
			break;

		case 'm':
			if (parse_mode(optarg, &mode))
				return EXIT_FAILURE;
			break;

		case 'h':
			show_usage(stdout);
			return EXIT_SUCCESS;

		case '?':
			show_error("unrecognized option '%s'.\n\n",
			           argv[optind - 1]);
			goto usage;

		case ':':
		default:
			show_error("unexpected option parsing error.\n\n");
			goto usage;
		}
	}

	argc -= optind;
	argv = &argv[optind];

	if (argc < 1)
		goto inval_argc;
	if (!strcmp("help", argv[0])) {
		show_usage(stdout);
		return EXIT_SUCCESS;
	}

	if (argc != 2)
		goto inval_argc;
	if (!strcmp("drain", argv[0]))
		cmd = DRAIN_CMD;
	else if (!strcmp("flush", argv[0]))
		cmd = FLUSH_CMD;
	else if (!strcmp("create", argv[0]))
		cmd = CREATE_CMD;
	else if (!strcmp("destroy", argv[0]))
		cmd = DESTROY_CMD;
	else
		cmd = INVAL_CMD;

	switch (cmd) {
	case DRAIN_CMD:
		ret = drain_mqueue(argv[1], follow);
		break;

	case FLUSH_CMD:
		ret = flush_mqueue(argv[1]);
		break;

	case CREATE_CMD:
		ret = create_mqueue(argv[1], depth, mode);
		break;

	case DESTROY_CMD:
		ret = destroy_mqueue(argv[1]);
		break;

	default:
		show_error("invalid command '%s'.\n", argv[0]);
		return EXIT_FAILURE;
	}

	return ret;

inval_argc:
	show_error("invalid number of arguments.\n\n");
usage:
	show_usage(stderr);

	return EXIT_FAILURE;
}
