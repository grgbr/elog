#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* For program_invocation_short_name(3) definition. */
#endif

#include <elog/elog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#define show_error(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#define USAGE \
"Usage: %1$s [OPTIONS]\n" \
"Sample application logging a 'hello world' message to stderr for eLog usage\n" \
"demonstration purpose.\n" \
"\n" \
"With OPTIONS:\n" \
"    -h|--help -- this help message\n"

static void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

static const struct elog_stdio_conf dflt = {
	.super.severity = ELOG_INFO_SEVERITY,
	.format         = ELOG_TAG_FMT
};

int
main(int argc, char * const argv[])
{
	int               ret;
	struct elog_stdio log;

	while (true) {
		static const struct option opts[] = {
			{ "help", no_argument, NULL, 'h' },
			{ NULL,   0,           NULL, 0 }
		};

		ret = getopt_long(argc, argv, ":h", opts, NULL);
		if (ret < 0)
			break;

		switch (ret) {
		case 'h':
			show_usage();
			return EXIT_SUCCESS;

		case ':':
		case '?':
			show_error("unrecognized option '%s'.\n\n",
			           argv[optind - 1]);
			goto error;

		default:
			show_error("unexpected option parsing error.\n\n");
			goto error;
		}
	}

	elog_init_stdio(&log, &dflt);

	elog_info(&log, "Hello World !");

	elog_fini_stdio(&log);

	return EXIT_SUCCESS;

error:
	show_usage();

	return EXIT_FAILURE;
}
