#ifndef _GNU_SOURCE
#define _GNU_SOURCE /* For program_invocation_short_name(3) definition. */
#endif

#include <elog/elog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#define show_error(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format, \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#define USAGE \
"Usage: %1$s [OPTIONS] <PATH> <MSG>\n" \
"Sample application logging the message given in argument into specified file\n" \
"for eLog usage demonstration purpose.\n" \
"\n" \
"With OPTIONS:\n" \
"    -t|--tag      <TAG>       -- log message using tag TAG\n" \
"                                 (defaults to `%1$s')\n" \
"    -a|--flags    <FILE_FLAG> -- open output log file using open(2) flag\n" \
"                                 FILE_FLAG (defaults to `nofollow')\n" \
"    -p|--perms    <MODE>      -- create output log file with MODE\n" \
"                                 permission bits set (defaults to `0640')\n" \
"    -s|--severity <SEVERITY>  -- log message with severity <= SEVERITY\n" \
"                                 (defaults to `notice')\n" \
"    -m|--format   <FORMAT>    -- format message according to FORMAT\n" \
"                                 specification, (defaults to `rfc3164,pid')\n" \
"    -f|--facility <FACILITY>  -- in RFC3164 mode, build priority field using\n" \
"                                 facility FACILITY (defaults to `user')\n" \
"    -h|--help                 -- this help message\n" \
"Where:\n" \
"    FILE_FLAG    := none|dflt|nofollow\n" \
"    SEVERITY     := dflt|emerg|alert|crit|err|warn|notice|info|debug\n" \
"    FORMAT       := none|dflt|<FORMAT_FLAGS>\n" \
"    FORMAT_FLAGS := <FORMAT_FLAG>[,<FORMAT_FLAGS>]\n" \
"    FORMAT_FLAG  := realtime|monotime|tag|pid|severity|rfc3164\n" \
"    FACILITY     := dflt|auth|authpriv|cron|daemon|ftp|lpr|mail|news|syslog|\n" \
"                    user|uucp|local0|local1|local2|local3|local4|local5|local6|\n" \
"                    local7\n" \
"With:\n" \
"    MODE -- file creation permission bits, octal integer with eXecute bits\n" \
"            rejected.\n" \
"    TAG  -- logging message tag, [1:31] bytes long string.\n"

static void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

static const struct elog_file_conf dflt = {
	.stdio = {
		.format   = ELOG_RFC3164_FMT | ELOG_TAG_FMT | ELOG_PID_FMT,
		.severity = ELOG_NOTICE_SEVERITY,
		.facility = LOG_USER
	},
	/* make path a mandatory argument. */
	.path  = NULL,
	/* by default, don't follow links when opening output file. */
	.flags = O_NOFOLLOW,
	/* by default, create output file with 0640 permissions */
	.mode  = S_IRUSR | S_IWUSR | S_IRGRP
};

int
main(int argc, char * const argv[])
{
	int ret;

	struct elog_parse     ctx;
	struct elog_file_conf conf;
	struct elog_stdio     log;

	elog_init_file_parse(&ctx, &conf, &dflt);

	while (true) {
		int                        oind;
		static const struct option opts[] = {
			{ "tag",      required_argument, NULL, 't' },
			{ "flags",    required_argument, NULL, 'a' },
			{ "perms",    required_argument, NULL, 'p' },
			{ "format",   required_argument, NULL, 'm' },
			{ "severity", required_argument, NULL, 's' },
			{ "facility", required_argument, NULL, 'f' },
			{ "help",     no_argument,       NULL, 'h' },
			{ NULL,       0,                 NULL,  0 }
		};

		ret = getopt_long(argc, argv, ":t:a:p:m:s:f:h", opts, &oind);
		if (ret < 0)
			/* End of command line option parsing. */
			break;

		switch (ret) {
		case 't':
			if (!elog_is_tag_valid(optarg)) {
				show_error("invalid tag '%s' specified.\n\n",
				           optarg);
				goto parse_error;
			}

			elog_setup(optarg, ELOG_DFLT_PID);
			break;

		case 'a':
			ret = elog_parse_file_flags(&ctx, &conf, optarg);
			break;

		case 'p':
			ret = elog_parse_file_mode(&ctx, &conf, optarg);
			break;

		case 'm':
			ret = elog_parse_format(&ctx,
			                        (struct elog_conf *)&conf,
			                        optarg);
			break;

		case 's':
			ret = elog_parse_severity(&ctx,
			                          (struct elog_conf *)&conf,
			                          optarg);
			break;

		case 'f':
			ret = elog_parse_facility(&ctx,
			                          (struct elog_conf *)&conf,
			                          optarg);
			break;

		case 'h':
			ret = EXIT_SUCCESS;
			goto fini_parse;

		case ':':
			show_error("option '%s' requires an argument.\n\n",
			           argv[optind - 1]);
			goto parse_error;

		case '?':
			show_error("unrecognized option '%s'.\n\n",
			           argv[optind - 1]);
			goto parse_error;

		default:
			show_error("unexpected option parsing error.\n\n");
			goto parse_error;
		}

		if (ret < 0)
			goto show_error;
	}

	if ((optind + 2) != argc) {
		show_error("invalid number of arguments.\n\n");
		goto parse_error;
	}

	ret = elog_parse_file_path(&ctx, &conf, argv[optind++]);
	if (ret)
		goto show_error;

	ret = elog_realize_parse(&ctx, (struct elog_conf *)&conf);
	if (ret)
		goto show_error;

	elog_fini_parse(&ctx);

	ret = elog_init_file(&log, &conf);
	if (ret) {
		show_error("cannot initialize logger: %s (%d).\n",
		           strerror(-ret),
		           -ret);
		return EXIT_FAILURE;
	}

	elog_notice(&log, "logging input message: %s", argv[optind]);

	elog_fini_file(&log);

	return EXIT_SUCCESS;

show_error:
	if (ret != -ENOMEM)
		show_error("%s.\n\n", ctx.error);
parse_error:
	ret = EXIT_FAILURE;
fini_parse:
	elog_fini_parse(&ctx);
	show_usage();

	return ret;
}
