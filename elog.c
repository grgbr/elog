#include "common.h"
#include <stroll/cdefs.h>
#include <utils/time.h>
#include <utils/string.h>
#include <utils/file.h>
#include <ctype.h>
#include <sys/uio.h>
#include <linux/taskstats.h>

#define ELOG_TAG_MAX_SIZE     TS_COMM_LEN
#define ELOG_PRIO_MAX_LEN     (5U)
#define ELOG_TIME_MAX_LEN     (17U)
#define ELOG_TAG_MAX_LEN      (ELOG_TAG_MAX_SIZE - 1)
#define ELOG_PID_MAX_LEN      (12U)
#define ELOG_SEVERITY_MAX_LEN (6U)

#define elog_assert_intern() \
	elog_assert(elog_tag_len); \
	elog_assert(strnlen(elog_tag, ELOG_TAG_MAX_SIZE) == elog_tag_len); \
	elog_assert(elog_pid > 0)

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

/******************************************************************************
 * Common parsing handling.
 ******************************************************************************/

/* Time related format flags */
#define ELOG_TIME_FMT \
	(ELOG_BOOTTIME_FMT | ELOG_PROCTIME_FMT)

#define elog_assert_dflt_severity(_severity) \
	elog_assert(!((_severity) & ~LOG_PRIMASK))

#define elog_assert_severity(_severity) \
	elog_assert(((_severity) == ELOG_CURRENT_SEVERITY) || \
	            !((_severity) & ~LOG_PRIMASK))

#define elog_assert_dflt_conf(_conf) \
	elog_assert(_conf); \
	elog_assert_dflt_severity((_conf)->severity)

#define elog_assert_conf(_conf) \
	elog_assert(_conf); \
	elog_assert_severity((_conf)->severity)

#define elog_assert_parse(_parse) \
	elog_assert(_parse); \
	elog_assert((_parse)->check); \
	elog_assert(!(_parse)->error)

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

static const char * const elog_severity_labels[] = {
	[ELOG_EMERG_SEVERITY]   = "emerg",
	[ELOG_ALERT_SEVERITY]   = "alert",
	[ELOG_CRIT_SEVERITY]    = "crit",
	[ELOG_ERR_SEVERITY]     = "err",
	[ELOG_WARNING_SEVERITY] = "warn",
	[ELOG_NOTICE_SEVERITY]  = "notice",
	[ELOG_INFO_SEVERITY]    = "info",
	[ELOG_DEBUG_SEVERITY]   = "debug"
};

const char *
elog_get_severity_label(int prio)
{
	elog_assert(!(prio & ~(LOG_FACMASK | LOG_PRIMASK)));

	return elog_severity_labels[prio & LOG_PRIMASK];
}

static bool __const __nothrow
elog_check_severity(enum elog_severity severity)
{
	return !(severity & ~LOG_PRIMASK);
}

static __elog_nonull(1, 3, 4) __nothrow
int
elog_parse_base_severity(struct elog_parse * __restrict  parse,
                         enum elog_severity              dflt,
                         enum elog_severity * __restrict severity,
                         const char * __restrict         arg)
{
	elog_assert_parse(parse);
	elog_assert_dflt_severity(dflt);
	elog_assert(severity);
	elog_assert(arg);

	enum elog_severity             svrt;
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
		*severity = arg[0] - '0';
		return 0;
	}

	svrt = elog_parse_kword(kwords, stroll_array_nr(kwords), arg);
	if (svrt >= 0) {
		*severity = svrt;
		return 0;
	}

	if (!strcmp(arg, "dflt")) {
		*severity = dflt;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &parse->error,
	                               "severity parsing error: "
	                               "invalid '%s' specifier",
	                               arg);
}

#if defined(CONFIG_ELOG_HAVE_FORMAT)

#define elog_assert_dflt_format(_format, _mask) \
	elog_assert(!((_format) & ~(_mask))); \
	elog_assert(((_format) & ELOG_TIME_FMT) != ELOG_TIME_FMT)

#define elog_assert_format(_format, _mask) \
	elog_assert_dflt_format(_format, _mask); \
	elog_assert(!((_format) & ELOG_PID_FMT) || ((_format) & ELOG_TAG_FMT));

struct elog_parse_format_context {
	int    dflt;
	int    flags;
	char * error;
};

static bool __const __nothrow
elog_check_format(int format, int mask)
{
	if (format & ~mask)
		return false;

	if ((format & ELOG_TIME_FMT) == ELOG_TIME_FMT)
		return false;

	return true;
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
		ELOG_INIT_KWORD("boottime", ELOG_BOOTTIME_FMT),
		ELOG_INIT_KWORD("proctime", ELOG_PROCTIME_FMT),
		ELOG_INIT_KWORD("tag",      ELOG_TAG_FMT),
		ELOG_INIT_KWORD("pid",      ELOG_PID_FMT),
		ELOG_INIT_KWORD("severity", ELOG_SEVERITY_FMT)
	};

	elog_assert_dflt_format(ctx->dflt, ~(0));
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

	ret = elog_parse_kword(kwords, stroll_array_nr(kwords), arg);
	elog_assert(ret);
	if (ret > 0) {
		ctx->flags |= ret;

		if (!elog_check_format(ctx->flags, ~(0)))
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

static __elog_nonull(1, 3, 4) __nothrow
int
elog_parse_format(struct elog_parse * __restrict parse,
                  int                            dflt,
                  int * __restrict               format,
                  char * __restrict              arg)
{
	elog_assert_parse(parse);
	elog_assert((dflt & ELOG_TIME_FMT) != ELOG_TIME_FMT);
	elog_assert(format);
	elog_assert(arg);

	int                              ret;
	struct elog_parse_format_context ctx = {
		.dflt  = dflt,
		.flags = 0,
		.error = NULL
	};

	ret = ustr_parse_each_token(arg, ',', elog_parse_format_flag, &ctx);
	if (ret >= 0) {
		elog_assert(!ctx.error);
		*format = ctx.flags;
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

#endif /* defined(CONFIG_ELOG_HAVE_FORMAT) */

#if defined(CONFIG_ELOG_HAVE_FACILITY)

#define elog_assert_dflt_facility(_facility) \
	elog_assert(!((_facility) & ~LOG_FACMASK))

#define elog_assert_facility(_facility) \
	elog_assert(_facility); \
	elog_assert(!((_facility) & ~LOG_FACMASK))

static const char * const elog_facility_labels[] = {
	[LOG_FAC(LOG_KERN)]     = "kernel",
	[LOG_FAC(LOG_USER)]     = "user",
	[LOG_FAC(LOG_MAIL)]     = "mail",
	[LOG_FAC(LOG_DAEMON)]   = "daemon",
	[LOG_FAC(LOG_AUTH)]     = "auth",
	[LOG_FAC(LOG_SYSLOG)]   = "syslog",
	[LOG_FAC(LOG_LPR)]      = "lpr",
	[LOG_FAC(LOG_NEWS)]     = "news",
	[LOG_FAC(LOG_UUCP)]     = "uucp",
	[LOG_FAC(LOG_CRON)]     = "cron",
	[LOG_FAC(LOG_AUTHPRIV)] = "authpriv",
	[LOG_FAC(LOG_FTP)]      = "ftp",
	[12]                    = "unknown",
	[13]                    = "unknown",
	[14]                    = "unknown",
	[15]                    = "unknown",
	[LOG_FAC(LOG_LOCAL0)]   = "local0",
	[LOG_FAC(LOG_LOCAL1)]   = "local1",
	[LOG_FAC(LOG_LOCAL2)]   = "local2",
	[LOG_FAC(LOG_LOCAL3)]   = "local3",
	[LOG_FAC(LOG_LOCAL4)]   = "local4",
	[LOG_FAC(LOG_LOCAL5)]   = "local5",
	[LOG_FAC(LOG_LOCAL6)]   = "local6",
	[LOG_FAC(LOG_LOCAL7)]   = "local7"
};

const char *
elog_get_facility_label(int prio)
{
	elog_assert(!(prio & ~(LOG_FACMASK | LOG_PRIMASK)));

	return elog_facility_labels[LOG_FAC(prio)];
}

static bool __const __nothrow
elog_check_facility(int facility)
{
	return facility && !(facility & ~LOG_FACMASK);
}

static __elog_nonull(1, 3, 4) __nothrow
int
elog_parse_facility(struct elog_parse * __restrict parse,
                    int                            dflt,
                    int * __restrict               facility,
                    const char * __restrict        arg)
{
	elog_assert_parse(parse);
	elog_assert_dflt_facility(dflt);
	elog_assert(facility);
	elog_assert(arg);

	int                            fac;
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

	fac = elog_parse_kword(kwords, stroll_array_nr(kwords), arg);
	if (fac >= 0) {
		*facility = fac;
		return 0;
	}

	if (!strcmp(arg, "dflt")) {
		*facility = dflt;
		return 0;
	}

	return elog_build_error_string(-ENOENT,
	                               &parse->error,
	                               "facility parsing error: "
	                               "invalid '%s' specifier",
	                               arg);
}

#endif /* defined(CONFIG_ELOG_HAVE_FACILITY) */

int
elog_parse_severity(struct elog_parse * __restrict parse,
                    struct elog_conf * __restrict  conf,
                    const char * __restrict        arg)
{
	return elog_parse_base_severity(parse,
	                                parse->dflt->severity,
	                                &conf->severity,
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

static int __elog_nonull(1, 2) __nothrow
elog_check_base(struct elog_parse * __restrict parse,
                struct elog_conf * __restrict  conf)
{
	elog_assert_parse(parse);
	elog_assert(conf);

	const char * error;

	if (!elog_check_severity(conf->severity)) {
		error = "invalid severity specified";
		goto err;
	}

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid log configuration: %s",
	                               error);
}

void
elog_init_parse(struct elog_parse * __restrict      parse,
                struct elog_conf * __restrict       conf,
                const struct elog_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_conf(dflt);

	*conf = *dflt;

	parse->check = elog_check_base;
	parse->error = NULL;
	parse->dflt = dflt;
}

void
elog_fini_parse(const struct elog_parse * __restrict parse)
{
	elog_assert(parse);

	free(parse->error);
}

/******************************************************************************
 * Common output helpers.
 ******************************************************************************/

ssize_t
elog_check_line(const char * __restrict line, size_t size)
{
	elog_assert(line);
	elog_assert(size);
	elog_assert(size <= ELOG_LINE_MAX);

	const char * chr = line;
	const char * end = &line[size];

	do {
		if (!*chr || *chr == '\n')
			break;

		if (!(isgraph(*chr) || isblank(*chr)))
			return -ENOMSG;

		chr++;
	} while (chr < end);

	return chr - line;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_tag(char * __restrict head, int format)
{
	elog_assert(head);
	elog_assert(format);
	elog_assert((format & ELOG_TIME_FMT) != ELOG_TIME_FMT);
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
	elog_assert_dflt_severity(severity);

	sprintf(head, "{%6s}", elog_severity_labels[severity]);

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
	len = (int)stroll_min((size_t)ret, len);

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

#define ELOG_STDIO_HEAD_MAX_LEN \
	(sizeof('[') + ELOG_TIME_MAX_LEN + sizeof(']') + sizeof(' ') + \
	 ELOG_TAG_MAX_LEN + ELOG_PID_MAX_LEN + sizeof(':') + sizeof(' ') + \
	 sizeof('{') + ELOG_SEVERITY_MAX_LEN + sizeof('}'))

#define ELOG_STDIO_FMT_MSK \
	(ELOG_BOOTTIME_FMT | ELOG_PROCTIME_FMT | \
	 ELOG_TAG_FMT | ELOG_PID_FMT | \
	 ELOG_SEVERITY_FMT)

#define elog_assert_dflt_stdio_conf(_conf) \
	elog_assert_dflt_conf(&(_conf)->super); \
	elog_assert_dflt_format((_conf)->format, ELOG_STDIO_FMT_MSK)

#define elog_assert_stdio_conf(_conf) \
	elog_assert_conf(&(_conf)->super); \
	elog_assert_format((_conf)->format, ELOG_STDIO_FMT_MSK)

#define elog_assert_stdio_parse(_parse) \
	elog_assert_parse(_parse); \
	elog_assert_dflt_stdio_conf((struct elog_stdio_conf *)((_parse)->dflt))

int
elog_parse_stdio_severity(struct elog_parse * __restrict      parse,
                          struct elog_stdio_conf * __restrict conf,
                          const char * __restrict             arg)
{
	elog_assert_stdio_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_base_severity(parse,
	                                parse->dflt->severity,
	                                &conf->super.severity,
	                                arg);
}

int
elog_parse_stdio_format(struct elog_parse * __restrict      parse,
                        struct elog_stdio_conf * __restrict conf,
                        char * __restrict                   arg)
{
	elog_assert_stdio_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_format(parse,
	                         ((struct elog_stdio_conf *)
	                          parse->dflt)->format,
	                         &conf->format,
	                         arg);
}

static int __elog_nonull(1, 2) __nothrow
elog_check_stdio(struct elog_parse * __restrict parse,
                 struct elog_conf * __restrict  conf)
{
	elog_assert_stdio_parse(parse);
	elog_assert(conf);

	struct elog_stdio_conf * stdio = (struct elog_stdio_conf *)conf;
	const char *             error;

	if (!elog_check_severity(stdio->super.severity)) {
		error = "invalid severity specified";
		goto err;
	}

	if (!elog_check_format(stdio->format, ELOG_STDIO_FMT_MSK)) {
		error = "invalid format flag(s) specified";
		goto err;
	}

	if (stdio->format & ELOG_PID_FMT)
		stdio->format |= ELOG_TAG_FMT;

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid stdlog configuration: %s",
	                               error);
}

void
elog_init_stdio_parse(struct elog_parse * __restrict            parse,
                      struct elog_stdio_conf * __restrict       conf,
                      const struct elog_stdio_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_stdio_conf(dflt);

	*conf = *dflt;

	parse->check = elog_check_stdio;
	parse->error = NULL;
	parse->dflt = &dflt->super;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_boottime(char * __restrict head)
{
	elog_assert(head);

	struct timespec tspec;

	utime_monotonic_now(&tspec);

	sprintf(head, "[%10ld.%06ld]", tspec.tv_sec, tspec.tv_nsec / 1000U);

	return ELOG_TIME_MAX_LEN + 2;
}

static size_t __elog_nonull(1) __nothrow
elog_fill_head_proctime(char * __restrict head)
{
	elog_assert(head);

	struct timespec tspec;

	utime_proc_now(&tspec);

	sprintf(head, "[%10ld.%06ld]", tspec.tv_sec, tspec.tv_nsec / 1000U);

	return ELOG_TIME_MAX_LEN + 2;
}

static size_t __elog_nonull(1, 3) __nothrow
elog_fill_stdio_head(char * __restrict                         head,
                     enum elog_severity                        severity,
                     const struct elog_stdio_conf * __restrict conf)
{
	elog_assert_stdio_conf(conf);

	size_t bytes = 0;

	if (conf->format & ELOG_BOOTTIME_FMT)
		bytes += elog_fill_head_boottime(head);
	else if (conf->format & ELOG_PROCTIME_FMT)
		bytes += elog_fill_head_proctime(head);

	if (conf->format & ELOG_TAG_FMT) {
		if (bytes)
			head[bytes++] = ' ';
		bytes += elog_fill_head_tag(&head[bytes], conf->format);
	}

	if (conf->format & ELOG_SEVERITY_FMT) {
		if (bytes)
			head[bytes++] = ' ';
		bytes += elog_fill_head_severity(&head[bytes], severity);
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

	if (severity > log->conf.super.severity)
		return;
	if (severity == ELOG_CURRENT_SEVERITY)
		severity = log->conf.super.severity;

	/* Cook standard message header according to setup... */
	hlen = elog_fill_stdio_head(log->line, severity, &log->conf);

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
				.iov_len  = stroll_min(hlen + mlen,
				                       sizeof(log->line))
			},
			{ /* ... then terminating newline character. */
				.iov_base = &nl,
				.iov_len = 1
			}
		};

		ret = writev(STDERR_FILENO, vecs, stroll_array_nr(vecs));
	} while ((ret < 0) && (errno == EINTR));
}

static void __elog_nonull(1) __nothrow
elog_close_stdio(struct elog * logger __unused)
{
	const struct elog_stdio * log __unused = (struct elog_stdio *)logger;

	elog_assert_stdio_conf(&log->conf);
}

static const struct elog_ops elog_stdio_ops = {
	.vlog  = elog_vlog_stdio,
	.close = elog_close_stdio
};

void
elog_reconf_stdio(struct elog_stdio * __restrict            logger,
                  const struct elog_stdio_conf * __restrict conf)
{
	elog_assert_base(&logger->super);
	elog_assert_stdio_conf(&logger->conf);
	elog_assert_stdio_conf(conf);

	logger->conf = *conf;

	if (logger->conf.format & ELOG_PID_FMT)
		logger->conf.format |= ELOG_TAG_FMT;
}

void
elog_init_stdio(struct elog_stdio * __restrict            logger,
                const struct elog_stdio_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_stdio_conf(conf);

	elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

	logger->super.ops = &elog_stdio_ops;
	logger->conf = *conf;

	/*
	 * Disable stdio buffering, the whole line being rendered into our own
	 * buffer.
	 */
	setvbuf(stderr, NULL, _IOLBF, 0);
	fflush_unlocked(stderr);
}

struct elog *
elog_create_stdio(const struct elog_stdio_conf * __restrict conf)
{
	elog_assert_stdio_conf(conf);

	struct elog_stdio * logger;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	elog_init_stdio(logger, conf);

	return &logger->super;
}

#endif /* defined(CONFIG_ELOG_STDIO) */

/******************************************************************************
 * Syslog I/Os handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_SYSLOG)

#define ELOG_SYSLOG_FMT_MSK \
	(ELOG_TAG_FMT | ELOG_PID_FMT)

#define elog_assert_dflt_syslog_conf(_conf) \
	elog_assert_dflt_conf(&(_conf)->super); \
	elog_assert_dflt_format((_conf)->format, ELOG_SYSLOG_FMT_MSK); \
	elog_assert_dflt_facility((_conf)->facility)

#define elog_assert_syslog_conf(_conf) \
	elog_assert_conf(&(_conf)->super); \
	elog_assert_format((_conf)->format, ELOG_SYSLOG_FMT_MSK); \
	elog_assert_facility((_conf)->facility)

#define elog_assert_syslog_parse(_parse) \
	elog_assert_parse(_parse); \
	elog_assert_dflt_syslog_conf((struct elog_syslog_conf *) \
	                             ((_parse)->dflt))

int
elog_parse_syslog_severity(struct elog_parse * __restrict       parse,
                           struct elog_syslog_conf * __restrict conf,
                           const char * __restrict              arg)
{
	elog_assert_syslog_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_base_severity(parse,
	                                parse->dflt->severity,
	                                &conf->super.severity,
	                                arg);
}

int
elog_parse_syslog_format(struct elog_parse * __restrict       parse,
                         struct elog_syslog_conf * __restrict conf,
                         char * __restrict                    arg)
{
	elog_assert_syslog_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_format(parse,
	                         ((struct elog_syslog_conf *)
	                          parse->dflt)->format,
	                         &conf->format,
	                         arg);
}

int
elog_parse_syslog_facility(struct elog_parse * __restrict       parse,
                           struct elog_syslog_conf * __restrict conf,
                           char * __restrict                    arg)
{
	elog_assert_syslog_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_facility(parse,
	                           ((struct elog_syslog_conf *)
	                            parse->dflt)->facility,
	                           &conf->facility,
	                           arg);
}

static int __elog_nonull(1, 2) __nothrow
elog_check_syslog(struct elog_parse * __restrict parse,
                  struct elog_conf * __restrict  conf)
{
	elog_assert_syslog_parse(parse);
	elog_assert(conf);

	struct elog_syslog_conf * syslog = (struct elog_syslog_conf *)conf;
	const char *              error;

	if (!elog_check_severity(syslog->super.severity)) {
		error = "invalid severity specified";
		goto err;
	}

	if (!elog_check_format(syslog->format, ELOG_SYSLOG_FMT_MSK)) {
		error = "invalid format flag(s) specified";
		goto err;
	}

	syslog->format |= ELOG_TAG_FMT;

	if (!elog_check_facility(syslog->facility)) {
		error = "missing / invalid specified facility";
		goto err;
	}

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid syslog configuration: %s",
	                               error);
}

void
elog_init_syslog_parse(struct elog_parse * __restrict             parse,
                       struct elog_syslog_conf * __restrict       conf,
                       const struct elog_syslog_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_syslog_conf(dflt);

	*conf = *dflt;

	parse->check = elog_check_syslog;
	parse->error = NULL;
	parse->dflt = &dflt->super;
}

static int elog_syslog_refcnt;

static void __elog_nonull(1)
elog_open_syslog_sock(const struct elog_syslog_conf * __restrict conf)
{
	elog_assert_syslog_conf(conf);

	if (!elog_syslog_refcnt) {
		elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

		openlog(elog_tag,
		        LOG_NDELAY |
		        ((conf->format & ELOG_PID_FMT) ? LOG_PID : 0),
		        conf->facility);

		elog_syslog_refcnt++;
	}
}

static void
elog_close_syslog_sock(void)
{
	elog_assert_intern();
	elog_assert(elog_syslog_refcnt > 0);

	if (--elog_syslog_refcnt)
		return;

	closelog();
}

static void __elog_nonull(1, 3) __printf(3, 0)
elog_vlog_syslog(struct elog *      logger,
                 enum elog_severity severity,
                 const char *       format,
                 va_list            args)

{
	struct elog_syslog * log = (struct elog_syslog *)logger;

	elog_assert_syslog_conf(&log->conf);

	if (severity > log->conf.super.severity)
		return;
	if (severity == ELOG_CURRENT_SEVERITY)
		severity = log->conf.super.severity;

	vsyslog(LOG_MAKEPRI(log->conf.facility, severity), format, args);
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

void
elog_reconf_syslog(struct elog_syslog * __restrict            logger,
                   const struct elog_syslog_conf * __restrict conf)
{
	elog_assert_base(&logger->super);
	elog_assert_syslog_conf(&logger->conf);
	elog_assert_syslog_conf(conf);

	logger->conf = *conf;

	logger->conf.format |= ELOG_TAG_FMT;
}

void
elog_init_syslog(struct elog_syslog * __restrict            logger,
                 const struct elog_syslog_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_syslog_conf(conf);

	elog_open_syslog_sock(conf);

	logger->super.ops = &elog_syslog_ops;
	logger->conf = *conf;
}

struct elog *
elog_create_syslog(const struct elog_syslog_conf * __restrict conf)
{
	elog_assert_syslog_conf(conf);

	struct elog_syslog * logger;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	elog_init_syslog(logger, conf);

	return &logger->super;
}

#endif /* defined(CONFIG_ELOG_SYSLOG) */

/******************************************************************************
 * Message queue  handling.
 ******************************************************************************/

#if defined(CONFIG_ELOG_MQUEUE_PARSER)

ssize_t
elog_parse_mqueue_msg(struct elog_mqueue_head * __restrict msg, size_t size)
{
	elog_assert(msg);
	elog_assert(size);
	elog_assert(size <= ELOG_LINE_MAX);

	ssize_t         blen;
	struct timespec now;
	struct timespec tstamp;

	if (msg->pid <= 0)
		return -ESRCH;

	if (msg->prio & ~(LOG_FACMASK | LOG_PRIMASK))
		return -EPROTO;

	if (msg->body < 1)
		return -EPROTO;

	if ((sizeof(*msg) + msg->body) >= size)
		return -EMSGSIZE;

	blen = elog_check_line(&msg->data[0], size - sizeof(*msg));
	if (blen <= msg->body)
		return (blen < 0) ? blen : -ENODATA;

	/*
	 * Copy content of msg->tstamp packed content to prevent from unaligned
	 * pointer accesses.
	 */
	tstamp = msg->tstamp;
	utime_boot_now(&now);
	if (utime_tspec_after(&tstamp, &now))
		/* Timestamp is in the future: fix it. */
		msg->tstamp = now;

	return blen - msg->body;
}

#endif /* defined(CONFIG_ELOG_MQUEUE_PARSER) */

#if defined(CONFIG_ELOG_MQUEUE)

#define elog_assert_dflt_mqueue_conf(_conf) \
	elog_assert_dflt_conf(&(_conf)->super); \
	elog_assert_dflt_facility((_conf)->facility); \
	elog_assert(!(_conf)->name || \
	            (umq_validate_name((_conf)->name) > 0))

#define elog_assert_mqueue_conf(_conf) \
	elog_assert_conf(&(_conf)->super); \
	elog_assert_facility((_conf)->facility); \
	elog_assert(umq_validate_name((_conf)->name) > 0)

#define elog_assert_mqueue_parse(_parse) \
	elog_assert_parse(_parse); \
	elog_assert_dflt_mqueue_conf((struct elog_mqueue_conf *) \
	                             ((_parse)->dflt))

int
elog_parse_mqueue_severity(struct elog_parse * __restrict       parse,
                           struct elog_mqueue_conf * __restrict conf,
                           const char * __restrict              arg)
{
	elog_assert_mqueue_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_base_severity(parse,
	                                parse->dflt->severity,
	                                &conf->super.severity,
	                                arg);
}

int
elog_parse_mqueue_facility(struct elog_parse * __restrict       parse,
                           struct elog_mqueue_conf * __restrict conf,
                           char * __restrict                    arg)
{
	elog_assert_mqueue_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	return elog_parse_facility(parse,
	                           ((struct elog_mqueue_conf *)
	                            parse->dflt)->facility,
	                           &conf->facility,
	                           arg);
}

int
elog_parse_mqueue_name(struct elog_parse * __restrict       parse,
                       struct elog_mqueue_conf * __restrict conf,
                       const char * __restrict              arg)
{
	elog_assert_mqueue_parse(parse);
	elog_assert(conf);
	elog_assert(arg);

	if (strcmp(arg, "dflt")) {
		ssize_t      len;
		const char * msg;

		len = umq_validate_name(arg);
		elog_assert(len);
		if (len > 0) {
			conf->name = arg;
			return 0;
		}

		switch (len) {
		case -EINVAL:
			msg = "invalid format";
			break;

		case -ENODATA:
			msg = "empty or missing specifier";
			break;

		case -ENAMETOOLONG:
			msg = "name too long";
			break;

		default:
			elog_assert(0);
		}

		return elog_build_error_string(
			len,
			&parse->error,
			"message queue name parsing error: %s",
			msg);
	}

	/* Set default. */
	conf->name = ((struct elog_mqueue_conf *)parse->dflt)->name;

	return 0;
}

static int __elog_nonull(1, 2) __nothrow
elog_check_mqueue(struct elog_parse * __restrict parse,
                  struct elog_conf * __restrict  conf)
{
	elog_assert_mqueue_parse(parse);
	elog_assert(conf);

	struct elog_mqueue_conf * mqueue = (struct elog_mqueue_conf *)conf;
	const char *              error;

	if (!elog_check_severity(mqueue->super.severity)) {
		error = "invalid severity specified";
		goto err;
	}

	if (!elog_check_facility(mqueue->facility)) {
		error = "missing / invalid specified facility";
		goto err;
	}

	if (!mqueue->name) {
		error = "missing message queue name";
		goto err;
	}

	return 0;

err:
	return elog_build_error_string(-EINVAL,
	                               &parse->error,
	                               "invalid mqlog configuration: %s",
	                               error);
}

void
elog_init_mqueue_parse(struct elog_parse * __restrict             parse,
                       struct elog_mqueue_conf * __restrict       conf,
                       const struct elog_mqueue_conf * __restrict dflt)
{
	elog_assert(parse);
	elog_assert(conf);
	elog_assert_dflt_mqueue_conf(dflt);

	*conf = *dflt;

	parse->check = elog_check_mqueue;
	parse->error = NULL;
	parse->dflt = &dflt->super;
}

void
elog_reconf_mqueue(struct elog_mqueue * __restrict            logger,
                   const struct elog_mqueue_conf * __restrict conf)
{
	elog_assert_base(&logger->super);
	elog_assert_mqueue_conf(&logger->conf);
	elog_assert(logger->fd >= 0);
	elog_assert_mqueue_conf(conf);
	elog_assert(conf->name);
	elog_assert(!strcmp(conf->name, logger->conf.name));

	logger->conf.super = conf->super;
	logger->conf.facility = conf->facility;
}

static void __elog_nonull(1, 3) __printf(3, 0) __nothrow
elog_vlog_mqueue(struct elog * __restrict logger,
                 enum elog_severity       severity,
                 const char * __restrict  format,
                 va_list                  args)
{
	struct elog_mqueue *      log = (struct elog_mqueue *)logger;
	struct elog_mqueue_head * head = (struct elog_mqueue_head *)log->line;
	size_t                    hlen = sizeof(*head) + elog_tag_len;
	size_t                    mlen;
	struct timespec           now;
	ssize_t                   ret;

	elog_assert_mqueue_conf(&log->conf);
	elog_assert(log->fd >= 0);

	if (severity > log->conf.super.severity)
		return;
	if (severity == ELOG_CURRENT_SEVERITY)
		severity = log->conf.super.severity;

	/*
	 * Then fill in the message body given in argument.
	 * elog_fill_line_msg() removes trailing newline characters if any.
	 */
	mlen = elog_fill_line_msg(&log->line[hlen],
	                          sizeof(log->line) - hlen,
	                          format,
	                          args);
	if (!mlen)
		/* Do not output messages with empty body. */
		return;

	/* Cook message header... */
	utime_boot_now(&now);
	head->tstamp = now;
	head->pid = elog_pid;
	head->prio = LOG_MAKEPRI(log->conf.facility, severity);
	head->body = (unsigned char)elog_tag_len;
	memcpy(head->data, elog_tag, elog_tag_len);

	/* Finally blindly write entire line. */
	do {
		ret = umq_send((mqd_t)log->fd, log->line, hlen + mlen, 0);
	} while (ret == -EINTR);
}

static void __elog_nonull(1)
elog_close_mqueue(struct elog * __restrict logger)
{
	struct elog_mqueue * log = (struct elog_mqueue *)logger;

	elog_assert_mqueue_conf(&log->conf);
	elog_assert(log->fd >= 0);

	umq_close(log->fd);
}

static const struct elog_ops elog_mqueue_ops = {
	.vlog  = elog_vlog_mqueue,
	.close = elog_close_mqueue
};

void
elog_init_mqueue_bymqd(struct elog_mqueue * __restrict            logger,
                       mqd_t                                      mqd,
                       const struct elog_mqueue_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert(mqd >= 0);
	elog_assert_mqueue_conf(conf);

	elog_setup(ELOG_DFLT_TAG, ELOG_DFLT_PID);

	logger->super.ops = &elog_mqueue_ops;
	logger->conf = *conf;
	logger->fd = mqd;
}

struct elog *
elog_create_mqueue_bymqd(mqd_t                                      mqd,
                         const struct elog_mqueue_conf * __restrict conf)
{
	elog_assert_mqueue_conf(conf);

	struct elog_mqueue * logger;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	elog_init_mqueue_bymqd(logger, mqd, conf);

	return &logger->super;
}

int
elog_init_mqueue(struct elog_mqueue * __restrict            logger,
                 const struct elog_mqueue_conf * __restrict conf)
{
	elog_assert(logger);
	elog_assert_mqueue_conf(conf);

	mqd_t          mqd;
	struct mq_attr attr;

	mqd = umq_open(conf->name, O_WRONLY | O_CLOEXEC | O_NONBLOCK);
	if (mqd < 0)
		return mqd;

	umq_getattr(mqd, &attr);
	if ((attr.mq_msgsize < (long)sizeof(logger->line)) ||
	    (attr.mq_maxmsg < 1)) {
		umq_close(mqd);
		return -EINVAL;
	}

	elog_init_mqueue_bymqd(logger, mqd, conf);

	return 0;
}

struct elog *
elog_create_mqueue(const struct elog_mqueue_conf * __restrict conf)
{
	elog_assert_mqueue_conf(conf);

	struct elog_mqueue * logger;
	int                  err;

	logger = malloc(sizeof(*logger));
	if (!logger)
		return NULL;

	err = elog_init_mqueue(logger, conf);
	if (err) {
		free(logger);
		errno = -err;
		return NULL;
	}

	return &logger->super;
}

#endif /* defined(CONFIG_ELOG_MQUEUE) */

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
		return -ENOMEM;

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
	elog_assert_severity(severity);
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
	elog_assert_severity(severity);
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
}
