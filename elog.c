#include "common.h"
#include <utils/time.h>
#include <utils/string.h>
#include <utils/file.h>
#include <sys/uio.h>
#include <linux/taskstats.h>

#define ELOG_TAG_MAX_SIZE     TS_COMM_LEN
#define ELOG_PRIO_MAX_LEN     (5U)
#define ELOG_REALTIME_MAX_LEN (27U)
#define ELOG_MONOTIME_MAX_LEN (17U)
#define ELOG_TAG_MAX_LEN      (ELOG_TAG_MAX_SIZE - 1)
#define ELOG_PID_MAX_LEN      (12U)
#define ELOG_SEVERITY_MAX_LEN (9U)

#if ELOG_REALTIME_MAX_LEN > ELOG_MONOTIME_MAX_LEN
#define ELOG_TIME_MAX_LEN ELOG_REALTIME_MAX_LEN
#else  /* !(ELOG_REALTIME_MAX_LEN > ELOG_MONOTIME_MAX_LEN) */
#define ELOG_TIME_MAX_LEN ELOG_MONOTIME_MAX_LEN
#endif /* ELOG_REALTIME_MAX_LEN > ELOG_MONOTIME_MAX_LEN */

#define ELOG_STDIO_HEAD_MAX_LEN \
	(sizeof('[') + ELOG_TIME_MAX_LEN + sizeof(']') + sizeof(' ') + \
	 ELOG_TAG_MAX_LEN + ELOG_PID_MAX_LEN + sizeof(':') + sizeof(' ') + \
	 sizeof('{') + ELOG_SEVERITY_MAX_LEN + sizeof('}'))

#define ELOG_RFC3164_HEAD_MAX_LEN \
	(ELOG_PRIO_MAX_LEN + \
	 ELOG_REALTIME_MAX_LEN + sizeof(' ') + \
	 HOST_NAME_MAX + sizeof(' ') + \
	 ELOG_TAG_MAX_LEN + ELOG_PID_MAX_LEN + sizeof(':') + sizeof(' ') + \
	 sizeof('{') + ELOG_SEVERITY_MAX_LEN + sizeof('}'))

#define elog_assert_intern() \
	elog_assert(elog_tag_len); \
	elog_assert(strnlen(elog_tag, ELOG_TAG_MAX_SIZE) == elog_tag_len); \
	elog_assert(elog_pid > 0); \
	elog_assert(elog_host_len); \
	elog_assert(strnlen(elog_host_name, sizeof(elog_host_name)) == \
	            elog_host_len)

#define elog_assert_ops(_ops) \
	elog_assert(_ops); \
	elog_assert((_ops)->vlog); \
	elog_assert((_ops)->close)

#define elog_assert_base(_logger) \
	elog_assert_intern(); \
	elog_assert(_logger); \
	elog_assert_ops((_logger)->ops)

static size_t elog_tag_len;
static char   elog_tag[ELOG_TAG_MAX_SIZE];
static pid_t  elog_pid = -1;
static size_t elog_host_len;
static char   elog_host_name[HOST_NAME_MAX + 1];

/******************************************************************************
 * Common parsing handling.
 ******************************************************************************/

/* Time related format flags, not compatible with RFC3164 mode. */
#define ELOG_TIME_FMT \
	(ELOG_REALTIME_FMT | ELOG_MONOTIME_FMT)

#define elog_assert_parse(_parse) \
	elog_assert(_parse); \
	elog_assert_dflt_conf((_parse)->dflt); \
	elog_assert((_parse)->check); \
	elog_assert(!(_parse)->error)

#define elog_assert_dflt_format(_format) \
	elog_assert(((_format) & ELOG_TIME_FMT) != ELOG_TIME_FMT); \
	elog_assert(!((_format) & ELOG_RFC3164_FMT) || \
	            !((_format) & ELOG_TIME_FMT))

#define elog_assert_severity(_severity) \
	elog_assert(!((_severity) & ~LOG_PRIMASK))

#define elog_assert_facility(_facility) \
	elog_assert(!((_facility) & ~LOG_FACMASK))

#define elog_assert_dflt_conf(_conf) \
	elog_assert(_conf); \
	elog_assert(((_conf)->format & ELOG_TIME_FMT) != ELOG_TIME_FMT); \
	elog_assert(!((_conf)->format & ELOG_PID_FMT) || \
	            ((_conf)->format & ELOG_TAG_FMT)); \
	elog_assert(((_conf)->severity == ELOG_DFLT_SEVERITY) || \
	            !((_conf)->severity & ~LOG_PRIMASK)); \
	elog_assert(!((_conf)->format & ELOG_RFC3164_FMT) || \
	            (!((_conf)->format & ELOG_TIME_FMT) && \
	             (_conf)->facility && \
	             !((_conf)->facility & ~LOG_FACMASK)))

#define elog_assert_conf(_conf) \
	elog_assert(_conf); \
	elog_assert(((_conf)->format & ELOG_TIME_FMT) != ELOG_TIME_FMT); \
	elog_assert(((_conf)->format & ELOG_TAG_FMT) || \
	            !((_conf)->format & ELOG_PID_FMT)); \
	elog_assert_severity((_conf)->severity); \
	elog_assert(!((_conf)->format & ELOG_RFC3164_FMT) || \
	            (!((_conf)->format & ELOG_TIME_FMT) && \
	             (_conf)->facility && \
	             !((_conf)->facility & ~LOG_FACMASK)))

struct elog_kword {
	const char * str;
	size_t       len;
	int          val;
};

#define ELOG_INIT_KWORD(_kword, _val) \
	{ .str = _kword, .len = sizeof(_kword) - 1, .val = _val }

static int __elog_nonull(1, 3) __pure __nothrow
elog_parse_kword(const struct elog_kword kwords[__restrict_arr],
                 unsigned int            nr,
                 const char * __restrict string)
{
	elog_assert(kwords);
	elog_assert(nr);
	elog_assert(string);
	elog_assert(string[0]);

	unsigned int              k;
	const struct elog_kword * kw;

	for (k = 0, kw = &kwords[k]; k < nr; k++, kw = &kwords[k])
		if (!strcmp(string, kw->str))
			return kw->val;

	return -ENOENT;
}

static int __elog_nonull(2, 3) __printf(3, 4) __nothrow
elog_build_error_string(int                     error,
                        char ** __restrict      string,
                        const char * __restrict format,
                        ...)
{
	elog_assert(error < 0);
	elog_assert(string);
	elog_assert(format);
	elog_assert(format[0]);

	va_list args;
	int     ret;

	if (*string)
		free(*string);

	va_start(args, format);
	ret = vasprintf(string, format, args);
	va_end(args);

	if (ret < 0) {
		/*
		 * As stated into asprintf(3) man page, when returning an error,
		 * the content of string is left undefined.
		 * Make sure *string points to NULL as we do not want
		 * elog_fini_parse() to free() undefined data.
		 */
		*string = NULL;
		return -ENOMEM;
	}

	return error;
}

ssize_t
elog_parse_tag(const char * tag)
{
	elog_assert(tag);

	int ret;

	ret = ustr_parse(tag, ELOG_TAG_MAX_SIZE);

	return (ret) ? ret : -ENODATA;
}

struct elog_parse_format_context {
	int    dflt;
	int    flags;
	char * error;
};

static bool __const __nothrow
elog_check_format(int format)
{
	int time = format & ELOG_TIME_FMT;

	return !((time == ELOG_TIME_FMT) ||
	         (time && (format & ELOG_RFC3164_FMT)));
}

static int __elog_nonull(1, 3) __nothrow
elog_parse_format_flag(char * __restrict arg,
                       size_t            len,
                       void *            data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	int                                ret;
	struct elog_parse_format_context * ctx = data;
	static const struct elog_kword     kwords[] = {
		ELOG_INIT_KWORD("realtime", ELOG_REALTIME_FMT),
		ELOG_INIT_KWORD("monotime", ELOG_MONOTIME_FMT),
		ELOG_INIT_KWORD("tag",      ELOG_TAG_FMT),
		ELOG_INIT_KWORD("pid",      ELOG_PID_FMT),
		ELOG_INIT_KWORD("severity", ELOG_SEVERITY_FMT),
		ELOG_INIT_KWORD("rfc3164",  ELOG_RFC3164_FMT)
	};

	elog_assert_dflt_format(ctx->dflt);
	elog_assert(!ctx->error);

	if (ustr_match_const_token(arg, len, "none")) {
		if (ctx->flags)
			/*
			 * When used, "none" must be the first keyword of a
			 * format specification string.
			 */
			return elog_build_error_string(
				-EINVAL,
				&ctx->error,
				"format parsing error: "
				"'none' specifier must come first");

		ctx->flags = 0;
		return 0;
	}

	ret = elog_parse_kword(kwords, array_nr(kwords), arg);
	elog_assert(ret);
	if (ret > 0) {
		ctx->flags |= ret;

		if (!elog_check_format(ctx->flags))
			return elog_build_error_string(
				-EINVAL,
				&ctx->error,
				"format parsing error: "
				"conflicting '%s' specifier",
				arg);

		return 0;
	}

	if (ustr_match_const_token(arg, len, "dflt")) {
		if (ctx->flags)
			/*
			 * When used, "dflt" must be the first keyword of a
			 * format specification string.
			 */
			return elog_build_error_string(
				-EINVAL,
				&ctx->error,
				"format parsing error: "
				"'dflt' specifier must come first");

		ctx->flags = ctx->dflt;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &ctx->error,
	                               "format parsing error: "
	                               "invalid '%s' specifier",
	                               arg);

}

int
elog_parse_format(struct elog_parse * __restrict parse,
                  struct elog_conf * __restrict  conf,
                  char * __restrict              arg)
{
	elog_assert_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	int                              ret;
	struct elog_parse_format_context ctx = {
		.dflt  = conf->format,
		.flags = 0,
		.error = NULL
	};

	ret = ustr_parse_each_token(arg, ',', elog_parse_format_flag, &ctx);
	if (ret >= 0) {
		elog_assert(!ctx.error);
		conf->format = ctx.flags;
		return 0;
	}

	switch (ret) {
	case -ENODATA:
		elog_assert(!ctx.error);
		return elog_build_error_string(-ENODATA,
		                               &parse->error,
		                               "format parsing error: "
		                               "empty or missing specifier");

	case -EINVAL:
	case -ENOENT:
		elog_assert(ctx.error);
		parse->error = ctx.error;
		return ret;

	case -ENOMEM:
		parse->error = NULL;
		return -ENOMEM;

	default:
		elog_assert(0);
	}

	unreachable();
}

static bool __const __nothrow
elog_check_severity(enum elog_severity severity)
{
	return !(severity & ~LOG_PRIMASK);
}

int
elog_parse_severity(struct elog_parse * __restrict parse,
                    struct elog_conf * __restrict  conf,
                    const char * __restrict        arg)
{
	elog_assert_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	enum elog_severity             severity;
	static const struct elog_kword kwords[] = {
		ELOG_INIT_KWORD("emerg",  ELOG_EMERG_SEVERITY),
		ELOG_INIT_KWORD("alert",  ELOG_ALERT_SEVERITY),
		ELOG_INIT_KWORD("crit",   ELOG_CRIT_SEVERITY),
		ELOG_INIT_KWORD("err",    ELOG_ERR_SEVERITY),
		ELOG_INIT_KWORD("warn",   ELOG_WARNING_SEVERITY),
		ELOG_INIT_KWORD("notice", ELOG_NOTICE_SEVERITY),
		ELOG_INIT_KWORD("info",   ELOG_INFO_SEVERITY),
		ELOG_INIT_KWORD("debug",  ELOG_DEBUG_SEVERITY)
	};

	if ((arg[0] >= '0') && (arg[0] <= '7') && arg[1] == '\0') {
		conf->severity = arg[0] - '0';
		return 0;
	}

	severity = elog_parse_kword(kwords, array_nr(kwords), arg);
	if (severity >= 0) {
		conf->severity = severity;
		return 0;
	}

	if (!strcmp(arg, "dflt")) {
		conf->severity = parse->dflt->severity;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &parse->error,
	                               "severity parsing error: "
	                               "invalid '%s' specifier",
	                               arg);
}

static bool __const __nothrow
elog_check_facility(int facility)
{
	return facility && !(facility & ~LOG_FACMASK);
}

int
elog_parse_facility(struct elog_parse * __restrict parse,
                    struct elog_conf * __restrict  conf,
                    const char * __restrict        arg)
{
	elog_assert_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	int                            facility;
	static const struct elog_kword kwords[] = {
		ELOG_INIT_KWORD("auth",     LOG_AUTH),
		ELOG_INIT_KWORD("authpriv", LOG_AUTHPRIV),
		ELOG_INIT_KWORD("cron",     LOG_CRON),
		ELOG_INIT_KWORD("daemon",   LOG_DAEMON),
		ELOG_INIT_KWORD("ftp",      LOG_FTP),
		ELOG_INIT_KWORD("lpr",      LOG_LPR),
		ELOG_INIT_KWORD("mail",     LOG_MAIL),
		ELOG_INIT_KWORD("news",     LOG_NEWS),
		ELOG_INIT_KWORD("syslog",   LOG_SYSLOG),
		ELOG_INIT_KWORD("user",     LOG_USER),
		ELOG_INIT_KWORD("uucp",     LOG_UUCP),
		ELOG_INIT_KWORD("local0",   LOG_LOCAL0),
		ELOG_INIT_KWORD("local1",   LOG_LOCAL1),
		ELOG_INIT_KWORD("local2",   LOG_LOCAL2),
		ELOG_INIT_KWORD("local3",   LOG_LOCAL3),
		ELOG_INIT_KWORD("local4",   LOG_LOCAL4),
		ELOG_INIT_KWORD("local5",   LOG_LOCAL5),
		ELOG_INIT_KWORD("local6",   LOG_LOCAL6),
		ELOG_INIT_KWORD("local7",   LOG_LOCAL7)
	};

	facility = elog_parse_kword(kwords, array_nr(kwords), arg);
	if (facility >= 0) {
		conf->facility = facility;
		return 0;
	}

	if (!strcmp(arg, "dflt")) {
		conf->facility = parse->dflt->facility;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &parse->error,
	                               "facility parsing error: "
	                               "invalid '%s' specifier",
	                               arg);
}

int
elog_realize_parse(struct elog_parse * __restrict parse,
                   struct elog_conf * __restrict  conf)
{
	elog_assert_parse(parse);
	elog_assert(conf);

	return parse->check(parse, conf);
}

void
elog_fini_parse(const struct elog_parse * __restrict parse)
{
	elog_assert(parse);
	elog_assert_dflt_conf(parse->dflt);
	elog_assert(parse->check);

	free(parse->error);
}

/******************************************************************************
 * Common output helpers.
 ******************************************************************************/

/* Generate string compliant with RFC3164. */
static size_t __elog_nonull(1) __nothrow
elog_fill_prio_field(char * __restrict  string,
                     enum elog_severity severity,
                     int                facility)
{
	elog_assert(string);
	elog_assert_severity(severity);
	elog_assert(facility);
	elog_assert_facility(facility);

	return (size_t)sprintf(string, "<%d>", LOG_MAKEPRI(facility, severity));
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_tag(char * __restrict head, int format)
{
	elog_assert(head);
	elog_assert(format & (ELOG_TAG_FMT | ELOG_PID_FMT));
	elog_assert(elog_parse_tag(elog_tag) == (ssize_t)elog_tag_len);

	memcpy(head, elog_tag, elog_tag_len);

	if (format & ELOG_PID_FMT) {
		elog_assert(elog_pid > 0);
		return elog_tag_len +
		       sprintf(&head[elog_tag_len], "[%d]:", elog_pid);
	}

	head[elog_tag_len] = ':';

	return elog_tag_len + 1;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_severity(char * __restrict head, enum elog_severity severity)
{
	elog_assert(head);
	elog_assert_severity(severity);

	static const char * const labels[] = {
		[ELOG_EMERG_SEVERITY]   = "EMERGENCY",
		[ELOG_ALERT_SEVERITY]   = "ALERT",
		[ELOG_CRIT_SEVERITY]    = "CRITICAL",
		[ELOG_ERR_SEVERITY]     = "ERROR",
		[ELOG_WARNING_SEVERITY] = "WARNING",
		[ELOG_NOTICE_SEVERITY]  = "NOTICE",
		[ELOG_INFO_SEVERITY]    = "INFO",
		[ELOG_DEBUG_SEVERITY]   = "DEBUG"
	};

	sprintf(head, "{%9s}", labels[severity]);

	return ELOG_SEVERITY_MAX_LEN + 2;
}

static size_t __elog_nonull(1, 3) __printf(3, 0) __nothrow
elog_fill_line_msg(char *       line,
                   size_t       len,
                   const char * format,
                   va_list      args)
{
	elog_assert(line);
	elog_assert(len);
	elog_assert(format);
	elog_assert(format[0]);

	int ret;

	ret = vsnprintf(line, len, format, args);
	elog_assert(ret >= 0);
	if (!ret)
		return 0;

	/* Fixup vsnprintf() returned length in case of overflow. */
	len = (int)umin((size_t)ret, len);

	/* Skip trailing newlines. */
	len -= ustr_rskip_char(line, '\n', len);
	if (!len)
		return 0;

	return len;
}

/******************************************************************************
 * Standard I/Os handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_STDIO)

#define ELOG_STDIO_FMT_MSK \
	(ELOG_REALTIME_FMT | ELOG_MONOTIME_FMT | ELOG_TAG_FMT | \
	 ELOG_PID_FMT | ELOG_SEVERITY_FMT | ELOG_RFC3164_FMT)

#define elog_assert_dflt_stdio_conf(_conf) \
	elog_assert_dflt_conf(_conf); \
	elog_assert(!((_conf)->format & ~ELOG_STDIO_FMT_MSK))

#define elog_assert_stdio_conf(_conf) \
	elog_assert_conf(_conf); \
	elog_assert(!((_conf)->format & ~ELOG_STDIO_FMT_MSK))

/* Generate string compliant with RFC3339. */
static size_t __elog_nonull(1) __nothrow
elog_fill_realtime_field(char * __restrict string)
{
	elog_assert(string);

	struct timespec tspec;
	struct tm       tmp;

	utime_realtime_now(&tspec);
	utime_gmtime_from_tspec(&tmp, &tspec);

	strftime(string, 20, "%FT%T", &tmp);
	sprintf(&string[19], ".%06ldZ", tspec.tv_nsec / 1000U);

	return ELOG_REALTIME_MAX_LEN;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_realtime(char * __restrict head)
{
	elog_assert(head);

	head[0] = '[';
	elog_fill_realtime_field(&head[1]);
	head[1 + ELOG_REALTIME_MAX_LEN] = ']';

	return ELOG_REALTIME_MAX_LEN + 2;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_monotime(char * __restrict head)
{
	elog_assert(head);

	struct timespec tspec;

	utime_monotonic_now(&tspec);

	sprintf(head, "[%10ld.%06ld]", tspec.tv_sec, tspec.tv_nsec / 1000U);

	return ELOG_MONOTIME_MAX_LEN + 2;
}

/*
 * Fill in RFC3164 header.
 * head must be ELOG_RFC3164_HEAD_MAX_LEN bytes long at least.
 */
static size_t __elog_nonull(1, 2) __nothrow
elog_fill_rfc3164_head(char * __restrict                   head,
                       const struct elog_conf * __restrict conf)
{
	elog_assert(conf->format & ELOG_RFC3164_FMT);
	elog_assert_severity(conf->severity);
	elog_assert(conf->facility);
	elog_assert_facility(conf->facility);

	size_t bytes;

	bytes = elog_fill_prio_field(head, conf->severity, conf->facility);
	bytes += elog_fill_realtime_field(&head[bytes]);

	head[bytes++] = ' ';
	memcpy(&head[bytes], elog_host_name, elog_host_len);
	bytes += elog_host_len;

	head[bytes++] = ' ';
	bytes += elog_fill_head_tag(&head[bytes], conf->format);

	if (conf->format & ELOG_SEVERITY_FMT) {
		head[bytes++] = ' ';
		bytes += elog_fill_head_severity(&head[bytes], conf->severity);
	}

	head[bytes++] = ' ';

	elog_assert(bytes <= ELOG_RFC3164_HEAD_MAX_LEN);

	return bytes;
}

static size_t __elog_nonull(1, 2) __nothrow
elog_fill_stdio_head(char * __restrict                   head,
                     const struct elog_conf * __restrict conf)
{
	elog_assert(!(conf->format & ELOG_RFC3164_FMT));
	elog_assert_severity(conf->severity);

	size_t bytes = 0;

	if (conf->format & ELOG_REALTIME_FMT)
		bytes += elog_fill_head_realtime(head);
	else if (conf->format & ELOG_MONOTIME_FMT)
		bytes += elog_fill_head_monotime(head);

	if (conf->format & ELOG_TAG_FMT) {
		if (bytes)
			head[bytes++] = ' ';
		bytes += elog_fill_head_tag(&head[bytes], conf->format);
	}

	if (conf->format & ELOG_SEVERITY_FMT) {
		if (bytes)
			head[bytes++] = ' ';
		bytes += elog_fill_head_severity(&head[bytes], conf->severity);
	}

	if (bytes)
		head[bytes++] = ' ';

	elog_assert(bytes <= ELOG_STDIO_HEAD_MAX_LEN);

	return bytes;
}

static void __elog_nonull(1, 3) __printf(3, 0) __nothrow
elog_vlog_stdio(struct elog * __restrict logger,
                enum elog_severity       severity,
                const char * __restrict  format,
                va_list                  args)
{
	struct elog_stdio * log = (struct elog_stdio *)logger;
	size_t              hlen;
	size_t              mlen;
	ssize_t             ret;

	elog_assert_stdio_conf(&log->conf);
	elog_assert(log->fd >= 0);

	if (severity > log->conf.severity)
		return;
	if (severity == ELOG_DFLT_SEVERITY)
		severity = log->conf.severity;

	if (log->conf.format & ELOG_RFC3164_FMT)
		/* Cook RFC3164 message header according to setup... */
		hlen = elog_fill_rfc3164_head(log->line, &log->conf);
	else
		/* Cook standard message header according to setup... */
		hlen = elog_fill_stdio_head(log->line, &log->conf);

	/*
	 * ...then fill in the message body given in argument.
	 * elog_fill_line_msg() removes trailing newline characters if any.
	 */
	mlen = elog_fill_line_msg(&log->line[hlen],
	                          sizeof(log->line) - hlen,
	                          format,
	                          args);
	if (!mlen)
		/* Do not output messages with empty body. */
		return;

	/* Finally blindly write entire line. */
	do {
		char               nl = '\n';
		const struct iovec vecs[] = {
			{ /* Include formated header and body... */
				.iov_base = log->line,
				.iov_len  = umin(hlen + mlen, sizeof(log->line))
			},
			{ /* ... then terminating newline character. */
				.iov_base = &nl,
				.iov_len = 1
			}
		};

		ret = writev(log->fd, vecs, array_nr(vecs));
	} while ((ret < 0) && (errno == EINTR));
}

static void __elog_nonull(1) __nothrow
elog_close_stdio(struct elog * logger __unused)
{
	const struct elog_stdio * log __unused = (struct elog_stdio *)logger;

	elog_assert_stdio_conf(&log->conf);
	elog_assert(log->fd >= 0);
}

static const struct elog_ops elog_stdio_ops = {
	.vlog  = elog_vlog_stdio,
	.close = elog_close_stdio
};

#if defined(CONFIG_ELOG_ASSERT)

void
elog_reconf_stdio(struct elog_stdio * __restrict      logger,
                  const struct elog_conf * __restrict conf)
{
	elog_assert_base(&logger->super);
	elog_assert_stdio_conf(&logger->conf);
	elog_assert(logger->fd >= 0);
	elog_assert_stdio_conf(conf);

	logger->conf = *conf;
}

#endif /* defined(CONFIG_ELOG_ASSERT) */

void
elog_init_stdio(struct elog_stdio * __restrict      logger,
                const struct elog_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_stdio_conf(conf);

	elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

	logger->super.ops = &elog_stdio_ops;
	logger->conf = *conf;
	logger->fd = STDERR_FILENO;

	/*
	 * Disable stdio buffering, the whole line being rendered into our own
	 * buffer.
	 */
	setvbuf(stderr, NULL, _IOLBF, 0);
	fflush_unlocked(stderr);
}

struct elog *
elog_create_stdio(const struct elog_conf * __restrict conf)
{
	elog_assert_stdio_conf(conf);

	struct elog_stdio * logger;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	elog_init_stdio(logger, conf);

	return &logger->super;
}

static int __elog_nonull(1, 2) __nothrow
_elog_check_stdio(struct elog_conf * __restrict conf,
                  const char ** __restrict      error)
{
	elog_assert(conf);
	elog_assert(error);

	if (conf->format & ~ELOG_STDIO_FMT_MSK) {
		*error = "unsupported format flag(s) specified";
		return -EINVAL;
	}

	if ((conf->format & ELOG_TIME_FMT) == ELOG_TIME_FMT) {
		*error = "conflicting time format flags specified";
		return -EINVAL;
	}

	if (!elog_check_severity(conf->severity)) {
		*error = "invalid severity specified";
		return -EINVAL;
	}

	if (conf->format & ELOG_RFC3164_FMT) {
		if (conf->format & ELOG_TIME_FMT) {
			*error = "conflicting time / rfc3164 format flags specified";
			return -EINVAL;
		}

		if (!elog_check_facility(conf->facility)) {
			*error = "missing / invalid specified facility";
			return -EINVAL;
		}

		conf->format |= ELOG_TAG_FMT;
	}

	if (conf->format & ELOG_PID_FMT)
		conf->format |= ELOG_TAG_FMT;

	return 0;
}

static int __elog_nonull(1, 2) __nothrow
elog_check_stdio(struct elog_parse * __restrict parse,
                 struct elog_conf * __restrict  conf)
{
	elog_assert(parse);
	elog_assert(conf);

	const char * error;

	if (!_elog_check_stdio(conf, &error))
		return 0;

	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid stdlog configuration: %s",
	                               error);
}

void
elog_init_stdio_parse(struct elog_parse * __restrict      parse,
                      struct elog_conf * __restrict       conf,
                      const struct elog_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_stdio_conf(dflt);

	*conf = *dflt;

	parse->dflt = dflt;
	parse->check = elog_check_stdio;
	parse->error = NULL;
}

#endif /* defined(CONFIG_ELOG_STDIO) */

/******************************************************************************
 * File I/Os handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_FILE)

#define elog_assert_dflt_file_conf(_conf) \
	elog_assert_dflt_conf(&(_conf)->stdio); \
	elog_assert(!(_conf)->path || \
	            (upath_validate_path_name((_conf)->path) > 0)); \
	elog_assert(!((_conf)->flags & ~O_NOFOLLOW)); \
	elog_assert(!((_conf)->mode & ~(S_IRUSR | S_IWUSR | \
	                                S_IRGRP | S_IWGRP | \
	                                S_IROTH | S_IWOTH)))

#define elog_assert_file_conf(_conf) \
	elog_assert_stdio_conf(&(_conf)->stdio); \
	elog_assert(upath_validate_path_name((_conf)->path) > 0); \
	elog_assert(!((_conf)->flags & ~O_NOFOLLOW)); \
	elog_assert((_conf)->mode); \
	elog_assert(!((_conf)->mode & ~(S_IRUSR | S_IWUSR | \
	                                S_IRGRP | S_IWGRP | \
	                                S_IROTH | S_IWOTH)))

#define elog_assert_file_parse(_parse) \
	elog_assert(_parse); \
	elog_assert_dflt_file_conf((struct elog_file_conf *)((_parse)->dflt)); \
	elog_assert((_parse)->check); \
	elog_assert(!(_parse)->error)

static int __elog_nonull(1, 2, 3) __nothrow
elog_parse_path(struct elog_parse * __restrict     parse,
                struct elog_file_conf * __restrict conf,
                const char * __restrict            arg,
                size_t                             len)
{
	elog_assert_file_parse(parse);
	elog_assert(conf);
	elog_assert(arg);
	elog_assert(len);

	if (!ustr_match_const_token(arg, len, "dflt")) {
		if (len >= PATH_MAX)
			return elog_build_error_string(
				-ENAMETOOLONG,
				&parse->error,
				"file path parsing error: "
				"path name too long");
		conf->path = arg;
	}
	else
		conf->path = ((struct elog_file_conf *)parse->dflt)->path;

	return 0;
}

int
elog_parse_file_path(struct elog_parse * __restrict     parse,
                     struct elog_file_conf * __restrict conf,
                     const char * __restrict            arg)
{
	elog_assert_file_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	size_t len;

	len = strnlen(arg, PATH_MAX);
	if (!len)
		return elog_build_error_string(-ENODATA,
		                               &parse->error,
		                               "file path parsing error: "
		                               "empty or missing specifier");

	return elog_parse_path(parse, conf, arg, len);
}

int
elog_parse_file_flags(struct elog_parse * __restrict     parse,
                      struct elog_file_conf * __restrict conf,
                      const char * __restrict            arg)
{
	elog_assert_file_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	if (!strcmp(arg, "nofollow")) {
		conf->flags = O_NOFOLLOW;
		return 0;
	}
	else if (!strcmp(arg, "none")) {
		conf->flags = 0;
		return 0;
	}
	else if (!strcmp(arg, "dflt")) {
		conf->flags = ((struct elog_file_conf *)parse->dflt)->flags;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &parse->error,
	                               "file flags parsing error: "
	                               "invalid '%s' specifier",
	                               arg);
}

static bool __const __nothrow
elog_check_file_mode(mode_t mode)
{
	return mode &&
	       !(mode &
	         ~(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH));
}

int
elog_parse_file_mode(struct elog_parse * __restrict     parse,
                     struct elog_file_conf * __restrict conf,
                     const char * __restrict            arg)
{
	elog_assert_file_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	mode_t mode;

	if (!strcmp(arg, "dflt")) {
		conf->mode = ((struct elog_file_conf *)parse->dflt)->mode;
		return 0;
	}

	if (upath_parse_mode(arg, &mode))
		return elog_build_error_string(-EINVAL,
		                               &parse->error,
		                               "file mode parsing error: "
		                               "invalid '%s' mode",
		                               arg);

	if (!elog_check_file_mode(mode))
		return elog_build_error_string(-EINVAL,
		                               &parse->error,
		                               "file mode parsing error: "
		                               "permissions '%s' not allowed",
		                               arg);

	conf->mode = mode;

	return 0;
}

static int __elog_nonull(1, 2) __nothrow
elog_check_file(struct elog_parse * __restrict parse,
                struct elog_conf * __restrict  stdio)
{
	elog_assert(parse);
	elog_assert(stdio);

	struct elog_file_conf * conf = (struct elog_file_conf *)stdio;
	const char *            error;

	if (_elog_check_stdio(stdio, &error))
		goto err;

	if (!conf->path) {
		error = "missing file path";
		goto err;
	}

	if (conf->flags & ~O_NOFOLLOW) {
		error = "invalid file flags specified";
		goto err;
	}

	if (!elog_check_file_mode(conf->mode)) {
		error = "invalid file mode specified";
		goto err;
	}

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid fslog configuration: %s",
	                               error);
}

void
elog_init_file_parse(struct elog_parse * __restrict           parse,
                     struct elog_file_conf * __restrict       conf,
                     const struct elog_file_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_file_conf(dflt);

	*conf = *dflt;

	parse->dflt = &dflt->stdio;
	parse->check = elog_check_file;
	parse->error = NULL;
}

static void __elog_nonull(1)
elog_close_file(struct elog * __restrict logger)
{
	struct elog_stdio * log = (struct elog_stdio *)logger;

	elog_assert_stdio_conf(&log->conf);
	elog_assert(log->fd >= 0);

	ufile_sync(log->fd);
	ufile_close(log->fd);
}

static const struct elog_ops elog_file_ops = {
	.vlog  = elog_vlog_stdio,
	.close = elog_close_file
};

int
elog_init_file(struct elog_stdio * __restrict           logger,
               const struct elog_file_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_file_conf(conf);

	int    fd;
	mode_t msk;

	msk = umask(~(conf->mode));
	fd = ufile_new(conf->path,
	               O_WRONLY | O_APPEND | O_CLOEXEC | conf->flags,
	               DEFFILEMODE);
	umask(msk);
	if (fd < 0)
		return fd;

	elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

	logger->super.ops = &elog_file_ops;
	logger->conf = conf->stdio;
	logger->fd = fd;

	return 0;
}

struct elog *
elog_create_file(const struct elog_file_conf * __restrict conf)
{
	elog_assert_file_conf(conf);

	struct elog_stdio * logger;
	int                 err;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	err = elog_init_file(logger, conf);
	if (err) {
		free(logger);
		errno = -err;
		return NULL;
	}

	return &logger->super;
}

#endif /* defined(CONFIG_ELOG_FILE) */

/******************************************************************************
 * Syslog I/Os handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_SYSLOG)

#include <utils/unsk.h>

#define ELOG_SYSLOG_FMT_MSK \
	(ELOG_TAG_FMT | ELOG_PID_FMT | ELOG_SEVERITY_FMT)

#define elog_assert_dflt_syslog_conf(_conf) \
	elog_assert_dflt_conf(_conf); \
	elog_assert(!((_conf)->format & ~ELOG_SYSLOG_FMT_MSK)); \
	elog_assert((_conf)->facility); \
	elog_assert_facility((_conf)->facility)

#define elog_assert_syslog_conf(_conf) \
	elog_assert_conf(_conf); \
	elog_assert(!((_conf)->format & ~ELOG_SYSLOG_FMT_MSK)); \
	elog_assert((_conf)->facility); \
	elog_assert_facility((_conf)->facility)

#define ELOG_SYSLOG_HEAD_MAX_LEN \
	(ELOG_PRIO_MAX_LEN + \
	 ELOG_TAG_MAX_LEN + ELOG_PID_MAX_LEN + sizeof(':') + sizeof(' ') + \
	 sizeof('{') + ELOG_SEVERITY_MAX_LEN + sizeof('}'))

static int         elog_syslog_refcnt;
static int         elog_syslog_fd = -1;
static const
struct sockaddr_un elog_syslog_peer = UNSK_INIT_NAMED_ADDR("/dev/log");
static const
socklen_t          elog_syslog_peer_sz = UNSK_INIT_NAMED_ADDR_LEN("/dev/log");

static int __nothrow
elog_open_syslog_sock(void)
{
	if (!elog_syslog_refcnt) {
		elog_syslog_fd = unsk_open(SOCK_DGRAM, SOCK_CLOEXEC);
		if (elog_syslog_fd < 0)
			return elog_syslog_fd;

		elog_syslog_refcnt++;
	}

	return 0;
}

static void
elog_close_syslog_sock(void)
{
	elog_assert(elog_syslog_refcnt > 0);

	if (--elog_syslog_refcnt)
		return;

	unsk_close(elog_syslog_fd);
}

/*
 * Fill in a header as expected by syslog daemon.
 * line must be ELOG_SYSLOG_LINE_MIN bytes long at least.
 */
static size_t __elog_nonull(1, 2) __nothrow
elog_fill_syslog_head(char * __restrict                   head,
                      const struct elog_conf * __restrict conf)
{
	elog_assert(head);
	elog_assert_syslog_conf(conf);

	size_t prio_len;
	size_t bytes = 0;

	prio_len = elog_fill_prio_field(head, conf->severity, conf->facility);
	head += prio_len;

	if (conf->format & ELOG_TAG_FMT)
		bytes = elog_fill_head_tag(head, conf->format);

	if (conf->format & ELOG_SEVERITY_FMT) {
		if (bytes)
			head[bytes++] = ' ';
		bytes += elog_fill_head_severity(&head[bytes], conf->severity);
	}

	if (bytes)
		head[bytes++] = ' ';

	elog_assert(bytes <= ELOG_SYSLOG_HEAD_MAX_LEN);

	return prio_len + bytes;
}

static void __elog_nonull(1, 3) __printf(3, 0) __nothrow
elog_vlog_syslog(struct elog *      logger,
                 enum elog_severity severity,
                 const char *       format,
                 va_list            args)

{
	struct elog_syslog * log = (struct elog_syslog *)logger;
	size_t               hlen;
	size_t               mlen;

	elog_assert_syslog_conf(&log->conf);

	if (severity > log->conf.severity)
		return;
	if (severity == ELOG_DFLT_SEVERITY)
		severity = log->conf.severity;

	/* Cook message header according to syslog daemon expectations... */
	hlen = elog_fill_syslog_head(log->line, &log->conf);

	/*
	 * ...then fill in the message body given in argument.
	 * elog_fill_line_msg() removes trailing newline characters if any. As
	 * syslog daemon insert line breaks itself, don't bother to add one.
	 */
	mlen = elog_fill_line_msg(&log->line[hlen],
	                          sizeof(log->line) - hlen,
	                          format,
	                          args);

	/*
	 * As stated into RFC3164, section 4.1:
	 * - total packet length MUST be >= 0 and <= 1024 bytes ;
	 * - sending a packet with no contents is worthless and SHOULD
	 *   NOT be transmitted.
	 */
	if (mlen) {
		const struct iovec  vec = {
			.iov_base = (void *)log->line,
			.iov_len  = hlen + mlen
		};
		const struct msghdr msg = {
			.msg_name       = (struct sockaddr *)&elog_syslog_peer,
			.msg_namelen    = elog_syslog_peer_sz,
			.msg_iov        = (struct iovec *)&vec,
			.msg_iovlen     = 1,
			0,
		};
		int                 ret;

		do {
			ret = unsk_send_dgram_msg(elog_syslog_fd, &msg, 0);
		} while (ret == -EINTR);

		elog_assert(ret != -EAGAIN);
	}
}

static void __elog_nonull(1)
elog_close_syslog(struct elog * logger __unused)
{
	struct elog_syslog * log __unused = (struct elog_syslog *)logger;

	elog_assert_syslog_conf(&log->conf);

	elog_close_syslog_sock();
}

static const struct elog_ops elog_syslog_ops = {
	.vlog  = elog_vlog_syslog,
	.close = elog_close_syslog
};

#if defined(CONFIG_ELOG_ASSERT)

void
elog_reconf_syslog(struct elog_syslog * __restrict     logger,
                   const struct elog_conf * __restrict conf)
{
	elog_assert_base(&logger->super);
	elog_assert_syslog_conf(&logger->conf);
	elog_assert_syslog_conf(conf);

	logger->conf = *conf;
}

#endif /* defined(CONFIG_ELOG_SYSLOG) */

int
elog_init_syslog(struct elog_syslog * __restrict     logger,
                 const struct elog_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_dflt_syslog_conf(conf);

	int err;

	err = elog_open_syslog_sock();
	if (err)
		return err;

	elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

	logger->super.ops = &elog_syslog_ops;
	logger->conf = *conf;

	return 0;
}

struct elog *
elog_create_syslog(const struct elog_conf * __restrict conf)
{
	elog_assert_dflt_syslog_conf(conf);

	struct elog_syslog * logger;
	int                  err;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	err = elog_init_syslog(logger, conf);
	if (err) {
		free(logger);
		errno = -err;
		return NULL;
	}

	return &logger->super;
}

static int __elog_nonull(1, 2) __nothrow
elog_check_syslog(struct elog_parse * __restrict parse,
                  struct elog_conf * __restrict  conf)
{
	elog_assert(parse);
	elog_assert(conf);

	const char * error;

	if (conf->format & ~ELOG_SYSLOG_FMT_MSK) {
		error = "unsupported format flag(s) specified";
		goto err;
	}

	if (!elog_check_severity(conf->severity)) {
		error = "invalid severity specified";
		goto err;
	}

	if (!elog_check_facility(conf->facility)) {
		error = "missing / invalid specified facility";
		goto err;
	}

	if (conf->format & ELOG_PID_FMT)
		conf->format |= ELOG_TAG_FMT;

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid syslog configuration: %s",
	                               error);
}

void
elog_init_syslog_parse(struct elog_parse * __restrict      parse,
                       struct elog_conf * __restrict       conf,
                       const struct elog_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_syslog_conf(dflt);

	*conf = *dflt;

	parse->dflt = dflt;
	parse->check = elog_check_syslog;
	parse->error = NULL;
}

#endif /* defined(CONFIG_ELOG_SYSLOG) */

/******************************************************************************
 * Multi-logger I/Os handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_MULTI)

static void __elog_nonull(1, 3) __printf(3, 0) __nothrow
elog_vlog_multi(struct elog *      logger,
                enum elog_severity severity,
                const char *       format,
                va_list            args)
{
	const struct elog_multi * multi = (struct elog_multi *)logger;
	unsigned int              l;

	elog_assert(!multi->nr || multi->subs);

	for (l = 0; l < multi->nr; l++) {
		va_list tmp;

		va_copy(tmp, args);
		elog_vlog(multi->subs[l], severity, format, tmp);
		va_end(tmp);
	}
}

static void __elog_nonull(1)
elog_close_multi(struct elog * logger)
{
	const struct elog_multi * multi = (struct elog_multi *)logger;
	unsigned int              l;

	elog_assert(!multi->nr || multi->subs);

	if (multi->release) {
		for (l = 0; l < multi->nr; l++)
			multi->release(multi->subs[l]);
	}

	free(multi->subs);
}

static const struct elog_ops elog_multi_ops = {
	.vlog  = elog_vlog_multi,
	.close = elog_close_multi
};

int
elog_register_multi_sublog(struct elog_multi * __restrict logger,
                           struct elog * __restrict       sublog)
{
	elog_assert_intern();
	elog_assert(logger);
	elog_assert_ops(logger->super.ops);
	elog_assert(!logger->nr || logger->subs);
	elog_assert(sublog);
	elog_assert_ops(sublog->ops);

	struct elog ** subs;

	subs = reallocarray(logger->subs,
	                    logger->nr + 1,
	                    sizeof(logger->subs[0]));
	if (!subs)
		return -errno;

	subs[logger->nr] = sublog;
	logger->subs = subs;
	logger->nr++;

	return 0;
}

void
elog_init_multi(struct elog_multi * __restrict logger,
                elog_release_fn *              release)
{
	elog_assert(logger);

	logger->super.ops = &elog_multi_ops;
	logger->nr = 0;
	logger->subs = NULL;
	logger->release = release;
}

#endif /* defined(CONFIG_ELOG_MULTI) */

/******************************************************************************
 * Top-level / generic logic.
 ******************************************************************************/

#if defined(CONFIG_ELOG_ASSERT)

void
elog_vlog(struct elog * __restrict logger,
          enum elog_severity       severity,
          const char * __restrict  format,
          va_list                  args)
{
	elog_assert_base(logger);
	elog_assert((severity == ELOG_DFLT_SEVERITY) ||
	            !(severity & ~LOG_PRIMASK));
	elog_assert(format);
	elog_assert(format[0]);

	logger->ops->vlog(logger, severity, format, args);
}

void
elog_log(struct elog * __restrict logger,
         enum elog_severity       severity,
         const char * __restrict  format,
         ...)
{
	elog_assert_base(logger);
	elog_assert((severity == ELOG_DFLT_SEVERITY) ||
	            !(severity & ~LOG_PRIMASK));
	elog_assert(format);
	elog_assert(format[0]);

	va_list args;

	va_start(args, format);
	logger->ops->vlog(logger, severity, format, args);
	va_end(args);
}

void
elog_fini(struct elog * __restrict logger)
{
	elog_assert_base(logger);

	logger->ops->close(logger);
}

#endif /* defined(CONFIG_ELOG_ASSERT) */

void
elog_destroy(struct elog * __restrict logger)
{
	elog_fini(logger);

	free(logger);
}

static void __elog_nonull(1) __nothrow
elog_setup_tag(const char * __restrict tag)
{
	elog_tag_len = strnlen(tag, ELOG_TAG_MAX_LEN);

	memcpy(elog_tag, tag, elog_tag_len);
	elog_tag[elog_tag_len] = '\0';
}

void
elog_setup(const char * __restrict tag, pid_t pid)
{
	if (tag)
		elog_setup_tag(tag);
	else if (!elog_tag_len)
		elog_setup_tag(program_invocation_short_name);

	if (pid > 0)
		elog_pid = pid;
	else if (elog_pid < 0)
		elog_pid = getpid();

	if (!elog_host_len) {
		int err __unused;

		err = gethostname(elog_host_name, sizeof(elog_host_name));
		elog_assert(!err);

		elog_host_len = strlen(elog_host_name);
	}
}
