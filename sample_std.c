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
"Usage: %1$s [OPTIONS] <MSG>\n" \
"Sample application logging the message given in argument to stderr for eLog\n" \
"usage demonstration purpose.\n" \
"\n" \
"With OPTIONS:\n" \
"    -t|--tag      <TAG>      -- log message using tag TAG\n" \
"                                (defaults to `%1$s')\n" \
"    -s|--severity <SEVERITY> -- log message with severity <= SEVERITY\n" \
"                                (defaults to `info')\n" \
"    -m|--format   <FORMAT>   -- format message according to FORMAT\n" \
"                                specification, (defaults to `tag')\n" \
"    -f|--facility <FACILITY> -- in RFC3164 mode, build priority field using\n" \
"                                using facility FACILITY (no default)\n" \
"    -h|--help                -- this help message\n" \
"Where:\n" \
"    SEVERITY := dflt|emerg|alert|crit|err|warn|notice|info|debug\n" \
"    FORMAT   := none|dflt|<FLAGS>\n" \
"    FLAGS    := <FLAG>[,<FLAGS>]\n" \
"    FLAG     := realtime|monotime|tag|pid|severity|rfc3164\n" \
"    FACILITY := dflt|auth|authpriv|cron|daemon|ftp|lpr|mail|news|syslog|user|\n" \
"                user|local0|local1|local2|local3|local4|local5|local6|local7\n" \
"With:\n" \
"    TAG -- logging message tag, [1:31] bytes long string.\n"

static void
show_usage(void)
{
	fprintf(stderr, USAGE, program_invocation_short_name);
}

static const struct elog_conf dflt = {
	.format   = ELOG_TAG_FMT,
	.severity = ELOG_INFO_SEVERITY,
	.facility = -1
};

int
main(int argc, char * const argv[])
{
	int ret;

	struct elog_parse ctx;
	struct elog_conf  conf;
	struct elog_stdio log;

	elog_init_stdio_parse(&ctx, &conf, &dflt);

	while (true) {
		static const struct option opts[] = {
			{ "tag",      required_argument, NULL, 't' },
			{ "format",   required_argument, NULL, 'm' },
			{ "severity", required_argument, NULL, 's' },
			{ "facility", required_argument, NULL, 'f' },
			{ "help",     no_argument,       NULL, 'h' },
			{ NULL,       0,                 NULL,  0 }
		};

		ret = getopt_long(argc, argv, ":t:m:s:f:h", opts, NULL);
		if (ret < 0) {
			/* End of command line option parsing. */
			ret = elog_realize_parse(&ctx, &conf);
			if (ret)
				goto show_error;
			break;
		}

		switch (ret) {
		case 't':
			if (!elog_is_tag_valid(optarg)) {
				show_error("invalid tag '%s' specified.\n\n",
				           optarg);
				goto parse_error;
			}

			elog_setup(optarg, ELOG_DFLT_PID);
			break;

		case 'm':
			ret = elog_parse_format(&ctx, &conf, optarg);
			break;

		case 's':
			ret = elog_parse_severity(&ctx, &conf, optarg);
			break;

		case 'f':
			ret = elog_parse_facility(&ctx, &conf, optarg);
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

	if (optind >= argc) {
		show_error("message unspecified.\n\n");
		goto parse_error;
	}

	elog_fini_parse(&ctx);

	elog_init_stdio(&log, &conf);

	elog_info(&log, "logging input message: %s", argv[optind]);

	elog_fini_stdio(&log);

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
