#ifndef _ELOG_H
#define _ELOG_H

#include <elog/config.h>
#include <utils/cdefs.h>
#include <stdbool.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/syslog.h>

#if defined(CONFIG_ELOG_ASSERT)

#define __elog_nonull(_arg_index, ...)

#else  /* !defined(CONFIG_ELOG_ASSERT) */

#define __elog_nonull(_arg_index, ...) \
	__nonull(_arg_index, ## __VA_ARGS__)

#endif /* defined(CONFIG_ELOG_ASSERT) */

#define ELOG_LINE_MAX (1024U)

struct elog;
struct elog_parse;

enum elog_format {
	ELOG_BOOTTIME_FMT = (1 << 0),
	ELOG_PROCTIME_FMT = (1 << 1),
	ELOG_TAG_FMT      = (1 << 2),
	ELOG_PID_FMT      = (1 << 3),
	ELOG_SEVERITY_FMT = (1 << 4)
};

enum elog_severity {
	ELOG_CURRENT_SEVERITY = -1,
	ELOG_EMERG_SEVERITY   = LOG_EMERG,
	ELOG_ALERT_SEVERITY   = LOG_ALERT,
	ELOG_CRIT_SEVERITY    = LOG_CRIT,
	ELOG_ERR_SEVERITY     = LOG_ERR,
	ELOG_WARNING_SEVERITY = LOG_WARNING,
	ELOG_NOTICE_SEVERITY  = LOG_NOTICE,
	ELOG_INFO_SEVERITY    = LOG_INFO,
	ELOG_DEBUG_SEVERITY   = LOG_DEBUG
};

extern const char * __pure __nothrow __leaf
elog_get_severity_label(int prio);

#if defined(CONFIG_ELOG_HAVE_FACILITY)

extern const char * __pure __nothrow __leaf
elog_get_facility_label(int prio);

#endif /* defined(CONFIG_ELOG_HAVE_FACILITY) */

extern ssize_t
elog_check_line(const char * __restrict line, size_t size)
	__elog_nonull(1) __nothrow __leaf __pure;

struct elog_conf {
	enum elog_severity severity;
};

typedef int (elog_check_fn)(struct elog_parse * __restrict parse,
                            struct elog_conf * __restrict  conf)
	__elog_nonull(1, 2);

struct elog_parse {
	elog_check_fn *          check;
	char *                   error;
	const struct elog_conf * dflt;
};

extern int
elog_parse_severity(struct elog_parse * __restrict  parse,
                    struct elog_conf * __restrict   conf,
                    const char * __restrict         arg)
	__elog_nonull(1, 2, 3) __nothrow __leaf __warn_result;

extern int
elog_realize_parse(struct elog_parse * __restrict parse,
                   struct elog_conf * __restrict  conf)
	__elog_nonull(1, 2) __nothrow;

extern void
elog_init_parse(struct elog_parse * __restrict      parse,
                struct elog_conf * __restrict       conf,
                const struct elog_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

extern void
elog_fini_parse(const struct elog_parse * __restrict parse)
	__elog_nonull(1) __nothrow __leaf;

struct elog_ops {
	void (*vlog) (struct elog * __restrict logger,
	              enum elog_severity       severity,
	              const char * __restrict  format,
	              va_list                  args);
	void (*close)(struct elog * logger);
};

struct elog {
	const struct elog_ops * ops;
};

#if defined(CONFIG_ELOG_ASSERT)

extern void
elog_vlog(struct elog * __restrict logger,
          enum elog_severity       severity,
          const char * __restrict  format,
          va_list                  args)
	__elog_nonull(1, 3) __printf(3, 0) __nothrow;

extern void
elog_log(struct elog * __restrict logger,
         enum elog_severity       severity,
         const char * __restrict  format,
         ...)
	__elog_nonull(1, 3) __printf(3, 4) __nothrow;

extern void
elog_fini(struct elog * logger) __elog_nonull(1);

#else  /* !defined(CONFIG_ELOG_ASSERT) */

static inline void __elog_nonull(1, 3) __nothrow
elog_vlog(struct elog * __restrict logger,
          enum elog_severity       severity,
          const char * __restrict  format,
          va_list                  args)
{
	logger->ops->vlog(logger, severity, format, args);
}

static inline void __elog_nonull(1, 3) __printf(3, 4) __nothrow
elog_log(struct elog * __restrict logger,
         enum elog_severity       severity,
         const char * __restrict  format,
         ...)
{
	va_list args;

	va_start(args, format);
	logger->ops->vlog(logger, severity, format, args);
	va_end(args);
}

static inline void __elog_nonull(1)
elog_fini(struct elog * logger)
{
	logger->ops->close(logger);
}

#endif /* defined(CONFIG_ELOG_ASSERT) */

#define elog_base(_logger) \
	((struct elog *)(_logger))

#define elog_current(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_CURRENT_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_emerg(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_EMERG_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_alert(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_ALERT_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_crit(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_CRIT_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_err(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_ERR_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_warn(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_WARNING_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_notice(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_NOTICE_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_info(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_INFO_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

#define elog_debug(_logger, _format, ...) \
	elog_log(elog_base(_logger), \
	         ELOG_DEBUG_SEVERITY, \
	         _format, \
	         ## __VA_ARGS__)

extern void
elog_destroy(struct elog * __restrict logger) __elog_nonull(1);

#define ELOG_DFLT_TAG (NULL)
#define ELOG_DFLT_PID (-1)

extern ssize_t
elog_parse_tag(const char * __restrict tag)
	__elog_nonull(1) __pure __nothrow __leaf;

static inline bool
elog_is_tag_valid(const char * __restrict tag)
{
	return elog_parse_tag(tag) > 0;
}

extern void
elog_setup(const char * __restrict tag, pid_t pid) __nothrow __leaf;

#if defined(CONFIG_ELOG_STDIO)

struct elog_stdio_conf {
	struct elog_conf super;
	int              format;
};

extern int
elog_parse_stdio_severity(struct elog_parse * __restrict      parse,
			  struct elog_stdio_conf * __restrict conf,
                          const char * __restrict             arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_stdio_format(struct elog_parse * __restrict      parse,
			struct elog_stdio_conf * __restrict conf,
                        char * __restrict                   arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern void
elog_init_stdio_parse(struct elog_parse * __restrict            parse,
                      struct elog_stdio_conf * __restrict       conf,
                      const struct elog_stdio_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

struct elog_stdio {
	struct elog            super;
	struct elog_stdio_conf conf;
	char                   line[ELOG_LINE_MAX];
};

extern void
elog_reconf_stdio(struct elog_stdio * __restrict            logger,
                  const struct elog_stdio_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

extern void
elog_init_stdio(struct elog_stdio * __restrict            logger,
                const struct elog_stdio_conf * __restrict conf)
	__elog_nonull(1, 2);

static inline void __elog_nonull(1)
elog_fini_stdio(struct elog_stdio * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog_stdio *
elog_create_stdio(const struct elog_stdio_conf * __restrict conf)
	__elog_nonull(1);

#endif /* defined(CONFIG_ELOG_STDIO) */

#if defined(CONFIG_ELOG_SYSLOG)

struct elog_syslog_conf {
	struct elog_conf super;
	int              format;
	int              facility;
};

extern int
elog_parse_syslog_severity(struct elog_parse * __restrict      parse,
			   struct elog_syslog_conf * __restrict conf,
                           const char * __restrict             arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_syslog_format(struct elog_parse * __restrict       parse,
			 struct elog_syslog_conf * __restrict conf,
                         char * __restrict                    arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_syslog_facility(struct elog_parse * __restrict       parse,
			   struct elog_syslog_conf * __restrict conf,
                           char * __restrict                    arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern void
elog_init_syslog_parse(struct elog_parse * __restrict             parse,
                       struct elog_syslog_conf * __restrict       conf,
                       const struct elog_syslog_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

struct elog_syslog {
	struct elog             super;
	struct elog_syslog_conf conf;
};

extern void
elog_reconf_syslog(struct elog_syslog * __restrict            logger,
                   const struct elog_syslog_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

extern void
elog_init_syslog(struct elog_syslog * __restrict            logger,
                 const struct elog_syslog_conf * __restrict conf)
	__elog_nonull(1, 2);

static inline void __elog_nonull(1)
elog_fini_syslog(struct elog_syslog * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog_syslog *
elog_create_syslog(const struct elog_syslog_conf * __restrict conf)
	__elog_nonull(1);

#endif /* defined(CONFIG_ELOG_SYSLOG) */

struct elog_mqueue_head {
	struct timespec tstamp;
	pid_t           pid;
	int             prio;
	unsigned char   body;
	char            data[0];
} __packed;

#if defined(CONFIG_ELOG_MQUEUE_PARSER)

extern ssize_t
elog_parse_mqueue_msg(struct elog_mqueue_head * __restrict msg, size_t size)
	__elog_nonull(1) __nothrow;

#endif /* defined(CONFIG_ELOG_MQUEUE_PARSER) */

#if defined(CONFIG_ELOG_MQUEUE)

#include <utils/mqueue.h>

struct elog_mqueue_conf {
	struct elog_conf super;
	int              facility;
	const char *     name;
};

extern int
elog_parse_mqueue_severity(struct elog_parse * __restrict      parse,
			   struct elog_mqueue_conf * __restrict conf,
                           const char * __restrict             arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_mqueue_facility(struct elog_parse * __restrict       parse,
			   struct elog_mqueue_conf * __restrict conf,
                           char * __restrict                    arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_mqueue_name(struct elog_parse * __restrict       parse,
                       struct elog_mqueue_conf * __restrict conf,
                       const char * __restrict              arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern void
elog_init_mqueue_parse(struct elog_parse * __restrict             parse,
                       struct elog_mqueue_conf * __restrict       conf,
                       const struct elog_mqueue_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;


struct elog_mqueue {
	struct elog             super;
	struct elog_mqueue_conf conf;
	char                    line[ELOG_LINE_MAX];
	mqd_t                   fd;
};

extern void
elog_reconf_mqueue(struct elog_mqueue * __restrict            logger,
                   const struct elog_mqueue_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

extern void
elog_init_mqueue_bymqd(struct elog_mqueue * __restrict            logger,
                       mqd_t                                      mqd,
                       const struct elog_mqueue_conf * __restrict conf)
	__elog_nonull(1, 3) __nothrow __leaf;

extern struct elog_mqueue *
elog_create_mqueue_bymqd(mqd_t                                      mqd,
                         const struct elog_mqueue_conf * __restrict conf)
	__elog_nonull(2) __nothrow __leaf;

extern int
elog_init_mqueue(struct elog_mqueue * __restrict            logger,
                 const struct elog_mqueue_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

extern struct elog_mqueue *
elog_create_mqueue(const struct elog_mqueue_conf * __restrict conf)
	__elog_nonull(1) __nothrow __leaf;

static inline void __elog_nonull(1)
elog_fini_mqueue(struct elog_mqueue * __restrict logger)
{
	elog_fini(&logger->super);
}

#endif /* defined(CONFIG_ELOG_MQUEUE) */

#if defined(CONFIG_ELOG_MULTI)

typedef void (elog_release_fn)(struct elog * __restrict logger)
	__elog_nonull(1);

struct elog_multi {
	struct elog       super;
	unsigned int      nr;
	struct elog **    subs;
	elog_release_fn * release;
};

extern int
elog_register_multi_sublog(struct elog_multi * __restrict logger,
                           struct elog * __restrict       sublog)
	__elog_nonull(1, 2) __nothrow __leaf;

extern void
elog_init_multi(struct elog_multi * __restrict logger,
                elog_release_fn *              release)
	__elog_nonull(1) __nothrow __leaf;

static inline void __elog_nonull(1)
elog_fini_multi(struct elog_multi * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog_multi *
elog_create_multi(elog_release_fn * release)
	__elog_nonull(1) __nothrow __warn_result;

#endif /* defined(CONFIG_ELOG_MULTI) */

#endif /* _ELOG_H */
