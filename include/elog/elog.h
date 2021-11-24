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
	ELOG_REALTIME_FMT = (1 << 0),
	ELOG_MONOTIME_FMT = (1 << 1),
	ELOG_TAG_FMT      = (1 << 2),
	ELOG_PID_FMT      = (1 << 3),
	ELOG_SEVERITY_FMT = (1 << 4),
	ELOG_RFC3164_FMT  = (1 << 5)
};

enum elog_severity {
	ELOG_DFLT_SEVERITY    = -1,
	ELOG_EMERG_SEVERITY   = LOG_EMERG,
	ELOG_ALERT_SEVERITY   = LOG_ALERT,
	ELOG_CRIT_SEVERITY    = LOG_CRIT,
	ELOG_ERR_SEVERITY     = LOG_ERR,
	ELOG_WARNING_SEVERITY = LOG_WARNING,
	ELOG_NOTICE_SEVERITY  = LOG_NOTICE,
	ELOG_INFO_SEVERITY    = LOG_INFO,
	ELOG_DEBUG_SEVERITY   = LOG_DEBUG
};

struct elog_conf {
	int                format;
	enum elog_severity severity;
	int                facility;
};

typedef int (elog_check_fn)(struct elog_parse * __restrict parse,
                            struct elog_conf * __restrict  conf)
	__elog_nonull(1, 2);

struct elog_parse {
	const struct elog_conf * dflt;
	elog_check_fn *          check;
	char *                   error;
};

extern int
elog_parse_format(struct elog_parse * __restrict parse,
                  struct elog_conf * __restrict  conf,
                  char * __restrict              arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_severity(struct elog_parse * __restrict parse,
                    struct elog_conf * __restrict  conf,
                    const char * __restrict        arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_facility(struct elog_parse * __restrict parse,
                    struct elog_conf * __restrict  conf,
                    const char * __restrict        arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_realize_parse(struct elog_parse * __restrict parse,
                   struct elog_conf * __restrict  conf)
	__elog_nonull(1, 2) __nothrow;

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

struct elog_stdio {
	struct elog      super;
	struct elog_conf conf;
	char             line[ELOG_LINE_MAX];
	int              fd;
};

extern void
elog_init_stdio_parse(struct elog_parse * __restrict      parse,
                      struct elog_conf * __restrict       conf,
                      const struct elog_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

#if defined(CONFIG_ELOG_ASSERT)

extern void
elog_reconf_stdio(struct elog_stdio * __restrict      logger,
                  const struct elog_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

#else  /* !defined(CONFIG_ELOG_ASSERT) */

static inline void __elog_nonull(1, 2) __nothrow
elog_reconf_stdio(struct elog_stdio * __restrict      logger,
                  const struct elog_conf * __restrict conf)
{
	logger->conf = *conf;
}

#endif /* defined(CONFIG_ELOG_ASSERT) */

extern void
elog_init_stdio(struct elog_stdio * __restrict      logger,
                const struct elog_conf * __restrict conf)
	__elog_nonull(1, 2);

static inline void __elog_nonull(1)
elog_fini_stdio(struct elog_stdio * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog *
elog_create_stdio(const struct elog_conf * __restrict conf) __elog_nonull(1);

#endif /* defined(CONFIG_ELOG_STDIO) */

#if defined(CONFIG_ELOG_FILE)

struct elog_file_conf {
	struct elog_conf stdio;
	const char *     path;
	int              flags;
	mode_t           mode;
};

extern int
elog_parse_file_path(struct elog_parse * __restrict     parse,
                     struct elog_file_conf * __restrict conf,
                     const char * __restrict            arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_file_flags(struct elog_parse * __restrict     parse,
                      struct elog_file_conf * __restrict conf,
                      const char * __restrict            arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern int
elog_parse_file_mode(struct elog_parse * __restrict     parse,
                     struct elog_file_conf * __restrict conf,
                     const char * __restrict            arg)
	__elog_nonull(1, 2, 3) __nothrow;

extern void
elog_init_file_parse(struct elog_parse * __restrict           parse,
                     struct elog_file_conf * __restrict       conf,
                     const struct elog_file_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

static inline void __elog_nonull(1, 2) __nothrow
elog_reconf_file(struct elog_stdio * __restrict      logger,
                 const struct elog_conf * __restrict conf)
{
	elog_reconf_stdio(logger, conf);
}

extern int
elog_init_file(struct elog_stdio * __restrict           logger,
               const struct elog_file_conf * __restrict conf)
	__elog_nonull(1, 2);

static inline void __elog_nonull(1)
elog_fini_file(struct elog_stdio * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog *
elog_create_file(const struct elog_file_conf * __restrict conf)
	__elog_nonull(1);

#endif /* defined(CONFIG_ELOG_FILE) */

#if defined(CONFIG_ELOG_SYSLOG)

struct elog_syslog {
	struct elog      super;
	struct elog_conf conf;
	char             line[ELOG_LINE_MAX];
};

extern void
elog_init_syslog_parse(struct elog_parse * __restrict      parse,
                       struct elog_conf * __restrict       conf,
                       const struct elog_conf * __restrict dflt)
	__elog_nonull(1, 2, 3) __nothrow __leaf;

#if defined(CONFIG_ELOG_ASSERT)

extern void
elog_reconf_syslog(struct elog_syslog * __restrict     logger,
                   const struct elog_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

#else  /* !defined(CONFIG_ELOG_ASSERT) */

static inline void __elog_nonull(1, 2) __nothrow
elog_reconf_syslog(struct elog_syslog * __restrict     logger,
                   const struct elog_conf * __restrict conf)
{
	logger->conf = *conf;
}

#endif /* defined(CONFIG_ELOG_ASSERT) */

extern int
elog_init_syslog(struct elog_syslog * __restrict     logger,
                 const struct elog_conf * __restrict conf)
	__elog_nonull(1, 2) __nothrow __leaf;

static inline void __elog_nonull(1)
elog_fini_syslog(struct elog_syslog * __restrict logger)
{
	elog_fini(&logger->super);
}

extern struct elog *
elog_create_syslog(const struct elog_conf * __restrict conf)
	__elog_nonull(1) __nothrow __leaf;

#endif /* defined(CONFIG_ELOG_SYSLOG) */

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
                           struct elog* __restrict        sublog)
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

#endif /* defined(CONFIG_ELOG_MULTI) */

#endif /* _ELOG_H */
