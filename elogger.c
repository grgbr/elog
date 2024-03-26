#include "common.h"
#include <stroll/cdefs.h>
#include <utils/pipe.h>
#include <utils/file.h>
#include <utils/poll.h>
#include <utils/signal.h>
#include <utils/string.h>
#include <limits.h>
#include <getopt.h>
#include <sys/wait.h>
#include <sysexits.h>

/******************************************************************************
 * Various helper functions...
 ******************************************************************************/

#define elogger_err(_format, ...) \
	fprintf(stderr, \
	        "%s: " _format "\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#if defined(CONFIG_ELOG_DEBUG)

#define elogger_debug(_format, ...) \
	fprintf(stderr, \
	        "%s: debug: " _format "\n", \
	        program_invocation_short_name, \
	        ## __VA_ARGS__)

#else  /* !defined(CONFIG_ELOG_DEBUG) */

#define elogger_debug(_format, ...) \
	        do { } while (0)

#endif /* defined(CONFIG_ELOG_DEBUG) */

static size_t __elog_nonull(1) __pure
elogger_skip_eol(const char * data, size_t size)
{
	elog_assert(data);
	elog_assert(size);

	const char * ptr = data;

	while ((ptr < &data[size]) && ((*ptr == '\n') || !*ptr))
		ptr++;

	return (size_t)(ptr - data);
}

static size_t __elog_nonull(1) __pure
elogger_skip_null(const char * data, size_t size)
{
	elog_assert(data);
	elog_assert(size);

	const char * ptr;

	ptr = memchr(data, '\0', size);

	return !ptr ? 0 : (size_t)(ptr + 1 - data);
}

static size_t __elog_nonull(1)
elogger_find_eol(char * data, size_t size)
{
	elog_assert(data);
	elog_assert(size);

	char * ptr = data;

	while ((ptr < &data[size]) && *ptr && (*ptr != '\n'))
		ptr++;

	if (ptr < &data[size]) {
		elog_assert(!*ptr || (*ptr == '\n'));
		*ptr = '\n';

		return (size_t)(ptr + 1 - data);
	}

	return 0;
}

static ssize_t __elog_nonull(2)
elogger_read_pipe(int fd, char * buff, size_t size)
{
	elog_assert(fd >= 0);
	elog_assert(buff);
	elog_assert(size);

	ssize_t ret;

	ret = upipe_read(fd, buff, size);
	if (ret <= 0)
		return (!ret) ? -EBADFD : ret;

	return ret;
}

static int
elogger_cleanup_fds(void)
{
	int err;
	
	err = ufd_close_fds(STDERR_FILENO + 1, ~0U);
	if (err)
		elogger_err("cannot close inherited file descriptors: %s (%d).",
		            strerror(-err),
		            -err);

	return err;
}

static unsigned int elogger_poller_refcnt;
static struct upoll elogger_poller;

static struct upoll *
elogger_acquire_poller(void)
{
	if (!elogger_poller_refcnt) {
		int err;

		err = upoll_open(&elogger_poller, 2);
		if (err) {
			elogger_err("cannot initialize poller: %s (%d).",
			            strerror(-err),
			            -err);
			errno = -err;
			return NULL;
		}
	}

	elogger_poller_refcnt++;

	return &elogger_poller;
}

#if defined(CONFIG_ELOG_DEBUG)

static void
elogger_release_poller(void)
{
	elog_assert(elogger_poller_refcnt);

	if (!(--elogger_poller_refcnt))
		upoll_close(&elogger_poller);
}

#else  /* !define(CONFIG_ELOG_DEBUG) */

static inline void elogger_release_poller(void) { }

#endif /* define(CONFIG_ELOG_DEBUG) */

static volatile sig_atomic_t elogger_child;
static volatile sig_atomic_t elogger_signo;

static void
elogger_handle_term_sig(int signo)
{
	if (elogger_signo)
		return;

	elogger_signo = signo;

	if (elogger_child > 0)
		/* kill(2) syscall is async-signal-safe... */
		kill(elogger_child, signo);
}

/******************************************************************************
 * Generic redirection handling
 ******************************************************************************/

#define elogger_assert_redir_ops(_ops) \
	elog_assert(_ops); \
	elog_assert((_ops)->start); \
	elog_assert((_ops)->connect_child); \
	elog_assert((_ops)->release)

#define elogger_assert_redir(_redir) \
	elog_assert(_redir); \
	elogger_assert_redir_ops((_redir)->ops)

struct elogger_redir;

struct elogger_redir_ops {
	void (*start)        (struct elogger_redir * __restrict redir);
	int  (*connect_child)(const struct elogger_redir * __restrict redir,
	                      int                                     child_fd);
	void (*release)      (struct elogger_redir * __restrict redir);
};

struct elogger_redir {
	const struct elogger_redir_ops * ops;
};

static void __elog_nonull(1)
elogger_dummy_start_redir(struct elogger_redir * __restrict redir __unused)
{
}

static void __elog_nonull(1)
elogger_start_redir(struct elogger_redir * __restrict redir)
{
	elogger_assert_redir(redir);

	redir->ops->start(redir);
}

static int __elog_nonull(1)
elogger_connect_redir_child(const struct elogger_redir * __restrict redir,
                            int                                     child_fd)
{
	elogger_assert_redir(redir);
	elog_assert(child_fd >= 0);

	return redir->ops->connect_child(redir, child_fd);
}

static void __elog_nonull(1)
elogger_release_redir(struct elogger_redir * __restrict redir)
{
	elogger_assert_redir(redir);

	return redir->ops->release(redir);
}

/******************************************************************************
 * /dev/null redirection
 ******************************************************************************/

struct elogger_chrdev_redir {
	struct elogger_redir super;
	int                  fd;
	unsigned int         ref;
};

static int __elog_nonull(1)
elogger_connect_chrdev_child(const struct elogger_redir * __restrict redir,
                             int                                     child_fd)
{
	struct elogger_chrdev_redir * dev;

	dev = (struct elogger_chrdev_redir *)redir;
	elog_assert(dev->fd >= 0);
	elog_assert(dev->ref);

	return ufd_dup2(dev->fd, child_fd);
}

#if defined(CONFIG_ELOG_DEBUG)

static void __elog_nonull(1)
elogger_release_chrdev_redir(struct elogger_redir * __restrict redir)
{
	struct elogger_chrdev_redir * dev;

	dev = (struct elogger_chrdev_redir *)redir;
	elog_assert(dev->fd >= 0);
	elog_assert(dev->ref);

	if (!(--dev->ref))
		ufile_close(dev->fd);
}

#else  /* !defined(CONFIG_ELOG_DEBUG) */

static inline void __elog_nonull(1)
elogger_release_chrdev_redir(struct elogger_redir * __restrict redir __unused)
{
}

#endif /* defined(CONFIG_ELOG_DEBUG) */

static const struct elogger_redir_ops elogger_chrdev_redir_ops = {
	.start         = elogger_dummy_start_redir,
	.connect_child = elogger_connect_chrdev_child,
	.release       = elogger_release_chrdev_redir
};

static struct elogger_chrdev_redir elogger_null = {
	.super.ops = &elogger_chrdev_redir_ops,
	.fd        = -1,
	.ref       = 0
};

static int __elog_nonull(1)
elogger_open_chrdev(const char * __restrict path)
{
	elog_assert(upath_validate_path_name(path) > 0);

	int         fd;
	struct stat st;
	int         err;

	fd = ufile_open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return fd;

	err = ufile_fstat(fd, &st);
	if (err < 0)
		goto close;

	if (!S_ISCHR(st.st_mode) || st.st_uid) {
		err = -EPERM;
		goto close;
	}

	return fd;

close:
#if defined(CONFIG_ELOG_DEBUG)
	ufile_close(fd);
#endif /* defined(CONFIG_ELOG_DEBUG) */

	return err;
}

static struct elogger_redir *
elogger_acquire_null(void)
{
	if (!elogger_null.ref) {
		elogger_null.fd = elogger_open_chrdev("/dev/null");
		if (elogger_null.fd < 0) {
			errno = -elogger_null.fd;
			return NULL;
		}
	}

	elogger_null.ref++;

	return (struct elogger_redir *)&elogger_null;
}

static int __elog_nonull(1)
elogger_build_null_redir(struct elogger_redir ** __restrict redir)
{
	elog_assert(redir);

	if (*redir) {
		elogger_err("cannot mix 'null' with multiple loggers.");
		return -EINVAL;
	}

	*redir = elogger_acquire_null();
	if (!*redir) {
		int err = errno;

		elogger_err("cannot create 'null' redirector: %s (%d).",
		            strerror(err),
		            err);
		return -err;
	}

	return 0;
}

/******************************************************************************
 * Anonymous / unamed pipe redirection.
 ******************************************************************************/

#define ELOGGER_PIPE_LINE_MAX  ELOG_LINE_MAX
#define ELOGGER_PIPE_BUFF_SIZE (2 * ELOGGER_PIPE_LINE_MAX)

#if ELOGGER_PIPE_BUFF_SIZE > PIPE_BUF
#error Invalid / unsupported ELOGGER_PIPE_BUFF_SIZE definition.
#endif

struct elogger_pipe_redir {
	struct elogger_redir super;
	struct upoll_worker  work;
	int                  fds[UPIPE_END_NR];
	size_t               bytes;
	char *               buff;
	struct elog_multi    log;
};

static struct elogger_pipe_redir * __elog_nonull(1) __const
elogger_pipe_redir_from_worker(const struct upoll_worker * __restrict worker)
{
	return containerof(worker, struct elogger_pipe_redir, work);
}

static void __elog_nonull(1, 2)
elogger_log_pipe_redir_line(struct elogger_pipe_redir * __restrict redir,
                            const char * __restrict                line,
                            size_t                                 len)
{
	elog_assert(redir);
	elog_assert(line);
	elog_assert(line[0]);
	elog_assert(len);
	elog_assert(line[len - 1] == '\n');

	elog_current(&redir->log, "%.*s", (int)(len - 1), line);
}

/**
 * Detect line boundaries and output entire lines.
 *
 * @param[inout] data first line byte to parse
 * @param[in]    size count  of bytes to parse
 * @param[in]    skip enable skipping of empty lines.
 *
 * @return number of unprocessed bytes
 * @retval 0  all input bytes have been consummed
 * @retval >0 count of bytes left since not completing an entire line
 */
static size_t __elog_nonull(1, 2)
elogger_process_pipe_redir_lines(struct elogger_pipe_redir * __restrict redir,
                                 char * __restrict                      data,
                                 size_t                                 size,
                                 bool                                   skip)
{
	elog_assert(redir);
	elog_assert(data);
	elog_assert(size);

	char * line = data;
	size_t sz = size;

	while (true) {
		size_t len;

		if (skip)
			len = elogger_skip_eol(line, sz);
		else
			len = elogger_skip_null(line, sz);
		sz -= len;
		if (!sz)
			return 0;

		line += len;
		len = elogger_find_eol(line, sz);
		if (!len)
			return sz;

		elogger_log_pipe_redir_line(redir, line, len);
		sz -= len;
		if (!sz)
			return 0;

		line += len;
	}
}

static void __elog_nonull(1)
elogger_process_pipe_redir_data(struct elogger_pipe_redir * __restrict redir,
                                size_t                                 unparsed)
{
	elog_assert(redir);
	elog_assert(redir->fds[UPIPE_READ_END] >= 0);
	elog_assert(redir->fds[UPIPE_WRITE_END] >= -1);
	elog_assert(redir->bytes <= ELOGGER_PIPE_BUFF_SIZE);
	elog_assert(redir->buff);
	elog_assert(unparsed);
	elog_assert((redir->bytes + unparsed) <= ELOGGER_PIPE_BUFF_SIZE);

	size_t bytes = redir->bytes;
	size_t len;

	if (!bytes) {
		/*
		 * No bytes left into the input buffer. Start an entire new line
		 * parsing cycle.
		 */
		len = elogger_process_pipe_redir_lines(redir,
		                                       redir->buff,
		                                       unparsed,
		                                       true);
		if (len) {
			elog_assert(len <= unparsed);
			goto relocate;
		}

		/* All bytes have been consummed: just return. */
		return;
	}

	/*
	 * There are some bytes left into the input buffer from a previous line
	 * parsing cycle.
	 * First, search for the next End-Of-Line marker to complete current
	 * line.
	 */
	len = elogger_find_eol(&redir->buff[bytes], unparsed);
	if (len) {
		/*
		 * End-Of-Line marker found: we may complete the current line.
		 * First, output entire current line, then continue processing
		 * remaining bytes if any...
		 */
		elogger_log_pipe_redir_line(redir, redir->buff, bytes + len);

		elog_assert(len <= unparsed);
		if (len != unparsed) {
			size_t left = unparsed - len;

			/*
			 * Parse remaining bytes, starting from the first
			 * unparsed byte. This may possibly complete multiple
			 * additional lines.
			 */
			len = elogger_process_pipe_redir_lines(
				redir, &redir->buff[bytes + len], left, true);
			if (len) {
				elog_assert(len <= left);
				goto relocate;
			}
		}

		/*
		 * All bytes have been consummed: clear remaining byte count and
		 * return.
		 */
		redir->bytes = 0;
	}
	else
		/*
		 * No line completed so far: just account for parsed bytes and
		 * return, hopping for line completion at next parsing cycle.
		 */
		redir->bytes = bytes + unparsed;

	return;

relocate:
	/*
	 * Last input bytes do not complete a full line. Hence, some bytes are
	 * still sitting into the input buffer. Relocate them to the very
	 * beginning of the input buffer if needed.
	 *
	 * First, calculate count of bytes consummed from the beginning of input
	 * buffer.
	 */
	bytes += unparsed - len;

	if (bytes)
		/*
		 * At least one line has been completed, i.e., some bytes have
		 * been consummed from the begining of input buffer, leaving a
		 * hole up to first unparsed byte: relocate bytes left to the
		 * very beginning of input buffer.
		 */
		memmove(redir->buff, &redir->buff[bytes], len);

	/* Update current line byte count. */
	redir->bytes = len;
}

static int __elog_nonull(1)
elogger_process_pipe_redir(struct elogger_pipe_redir * redir)
{
	elog_assert(redir);
	elog_assert(redir->fds[UPIPE_READ_END] >= 0);
	elog_assert(redir->fds[UPIPE_WRITE_END] >= -1);
	elog_assert(redir->bytes <= ELOGGER_PIPE_BUFF_SIZE);
	elog_assert(redir->buff);

	ssize_t ret;
	int     fd = redir->fds[UPIPE_READ_END];

	if (redir->bytes >= ELOGGER_PIPE_LINE_MAX) {
		/*
		 * Current line byte count exceeds available storage / maximum
		 * input line length: purge all data up to next End-Of-Line
		 * marker (indicating a fresh new line start).
		 */
		size_t len;

		while (true) {
			ret = elogger_read_pipe(fd,
			                        redir->buff,
			                        ELOGGER_PIPE_BUFF_SIZE);
			if (ret < 0)
				return ret;

			len = elogger_find_eol(redir->buff, (size_t)ret);
			elog_assert(len <= (size_t)ret);
			if (len)
				/* Found beginning of a new line. */
				break;

			if ((size_t)ret < ELOGGER_PIPE_BUFF_SIZE)
				/* No more data to read from pipe. */
				return -EAGAIN;
		}

		redir->bytes = 0;

		len = (size_t)ret - len;
		if (len) {
			memmove(redir->buff, &redir->buff[len], len);
			elogger_process_pipe_redir_data(redir, len);
		}

		if ((size_t)ret < ELOGGER_PIPE_BUFF_SIZE)
			/* No more data to read from pipe. */
			return -EAGAIN;
	}

	ret = elogger_read_pipe(fd,
	                        &redir->buff[redir->bytes],
	                        ELOGGER_PIPE_BUFF_SIZE - redir->bytes);
	if (ret < 0)
		return ret;

	elogger_process_pipe_redir_data(redir, (size_t)ret);

	return 0;
}

static void __elog_nonull(1)
elogger_close_pipe_redir_rdend(struct elogger_pipe_redir * __restrict redir)
{
	elog_assert(redir->fds[UPIPE_READ_END] >= 0);
	elog_assert(redir->fds[UPIPE_WRITE_END] >= -1);
	elog_assert(redir->buff);

	upoll_unregister(&elogger_poller, redir->fds[UPIPE_READ_END]);
	upipe_close(redir->fds[UPIPE_READ_END]);
	redir->fds[UPIPE_READ_END] = -1;
}

static int __elog_nonull(1, 3)
elogger_dispatch_pipe_redir(struct upoll_worker * worker,
                            uint32_t              state __unused,
                            const struct upoll *  poller __unused)
{
	elog_assert(worker);
	elog_assert(state);
	elog_assert(!(state & EPOLLRDHUP));
	elog_assert(!(state & EPOLLPRI));
	elog_assert(!(state & EPOLLERR));
	elog_assert(state & (EPOLLIN | EPOLLHUP));
	elog_assert(poller);

	struct elogger_pipe_redir * redir;
	int                         ret = 0;

#if defined(ELOG_DEBUG)
	if (state & EPOLLHUP)
		/*
		 * Hang up happened on the pipe's (read end) file descriptor,
		 * meaning that pipe's write end has been closed.
		 * Subsequent reads from the read end will return 0 (end of
		 * file) only after all outstanding data in the channel has been
		 * consumed.
		 */
		elogger_debug("pipe's write end has been closed.");
#endif /* defined(ELOG_DEBUG) */

	/* Process available pipe's input data. */
	redir = elogger_pipe_redir_from_worker(worker);
	ret = elogger_process_pipe_redir(redir);

	switch (ret) {
	case 0:
	case -EAGAIN:
		return 0;

	case -EBADFD:
		/*
		 * Pipe's write end closed and all outstanding data have been
		 * consummed. Just close read end and return.
		 */
		elogger_close_pipe_redir_rdend(redir);
		return -ESHUTDOWN;

	case -EINTR:
		return -EINTR;

	default:
		elog_assert(0);
	}

	unreachable();
}

static void __elog_nonull(1)
elogger_start_pipe_redir(struct elogger_redir * redir)
{
	struct elogger_pipe_redir * pipe = (struct elogger_pipe_redir *)redir;

	elog_assert(pipe->fds[UPIPE_READ_END] >= 0);
	elog_assert(pipe->fds[UPIPE_WRITE_END] >= 0);
	elog_assert(pipe->buff);

	upipe_close(pipe->fds[UPIPE_WRITE_END]);
	pipe->fds[UPIPE_WRITE_END] = -1;
}

static int __elog_nonull(1)
elogger_connect_pipe_child(const struct elogger_redir * __restrict redir,
                           int                                     child_fd)
{
	int fd = ((struct elogger_pipe_redir *)redir)->fds[UPIPE_WRITE_END];

	elog_assert(fd >= 0);
	
	return ufd_dup2(fd, child_fd);
}

#if defined(CONFIG_ELOG_DEBUG)

static void __elog_nonull(1)
elog_close_pipe_redir(struct elogger_pipe_redir * __restrict redir)
{
	elog_assert(redir->fds[UPIPE_READ_END] >= -1);
	elog_assert(redir->fds[UPIPE_WRITE_END] >= -1);
	elog_assert(redir->buff);

	if (redir->fds[UPIPE_READ_END] >= 0) {
		upoll_unregister(&elogger_poller, redir->fds[UPIPE_READ_END]);
		upipe_close(redir->fds[UPIPE_READ_END]);
	}

	if (redir->fds[UPIPE_WRITE_END] >= 0)
		upipe_close(redir->fds[UPIPE_WRITE_END]);

	elogger_release_poller();

	free(redir->buff);

	elog_fini_multi(&redir->log);
}

static void __elog_nonull(1)
elogger_release_pipe_redir(struct elogger_redir * __restrict redir)
{
	struct elogger_pipe_redir * pipe = (struct elogger_pipe_redir *)redir;

	elog_close_pipe_redir(pipe);

	free(pipe);
}

#else  /* !defined(CONFIG_ELOG_DEBUG) */

static void __elog_nonull(1)
elog_close_pipe_redir(struct elogger_pipe_redir * __restrict redir)
{
	elog_assert(redir->fds[UPIPE_READ_END] >= -1);
	elog_assert(redir->fds[UPIPE_WRITE_END] >= -1);
	elog_assert(redir->buff);

	if (redir->fds[UPIPE_READ_END] >= 0)
		upoll_unregister(&elogger_poller, redir->fds[UPIPE_READ_END]);

	elogger_release_poller();

	elog_fini_multi(&redir->log);
}

static void __elog_nonull(1)
elogger_release_pipe_redir(struct elogger_redir * __restrict redir)
{
	elog_close_pipe_redir((struct elogger_pipe_redir *)redir);
}

#endif /* defined(CONFIG_ELOG_DEBUG) */

static const struct elogger_redir_ops elogger_pipe_redir_ops = {
	.start         = elogger_start_pipe_redir,
	.connect_child = elogger_connect_pipe_child,
	.release       = elogger_release_pipe_redir
};

static int __elog_nonull(1)
elogger_open_pipe_redir(struct elogger_pipe_redir * __restrict redir)
{
	struct upoll * poll;
	int            err;

	redir->buff = malloc(ELOGGER_PIPE_BUFF_SIZE);
	if (!redir->buff)
		return -errno;

	err = upipe_open_anon(redir->fds, O_NONBLOCK);
	if (err)
		goto free;

	poll = elogger_acquire_poller();
	if (!poll) {
		err = -errno;
		goto close;
	}

	redir->work.dispatch = elogger_dispatch_pipe_redir;
	err = upoll_register(poll,
	                     redir->fds[UPIPE_READ_END],
	                     EPOLLIN,
	                     &redir->work);
	if (err)
		goto release;

	redir->bytes = 0;
#if defined(CONFIG_ELOG_DEBUG)
	elog_init_multi(&redir->log, elog_destroy);
#else  /* !defined(CONFIG_ELOG_DEBUG) */
	elog_init_multi(&redir->log, elog_fini);
#endif /* defined(CONFIG_ELOG_DEBUG) */

	return 0;

release:
	elogger_release_poller();
close:
#if defined(CONFIG_ELOG_DEBUG)
	upipe_close(redir->fds[UPIPE_READ_END]);
	upipe_close(redir->fds[UPIPE_WRITE_END]);
#endif /* defined(CONFIG_ELOG_DEBUG) */
free:
#if defined(CONFIG_ELOG_DEBUG)
	free(redir->buff);
#endif /* defined(CONFIG_ELOG_DEBUG) */

	return err;
}

static struct elogger_redir *
elogger_acquire_pipe_redir(void)
{
	struct elogger_pipe_redir * redir;
	int                         err;

	redir = malloc(sizeof(*redir));
	if (!redir)
		return NULL;

	err = elogger_open_pipe_redir(redir);
	if (err) {
		free(redir);
		errno = -err;
		return NULL;
	}

	redir->super.ops = &elogger_pipe_redir_ops;

	return &redir->super;
}

/******************************************************************************
 * Parsing and logger builders.
 ******************************************************************************/

/*
 * Internal fields are constify'ed here since ustr_parse_token_fn take a non
 * const (void *) as context / last argument.
 */
struct elogger_context {
	struct elog_parse                   parse;
	struct elog_conf * const            conf;
	unsigned int const                  count;
	ustr_parse_token_fn * const * const parsers;
};

static int __elog_nonull(1, 2, 3)
elogger_finalize_parsing(struct elogger_context * __restrict ctx,
                         char * __restrict                   spec,
                         const char * __restrict             pref)
{
	elog_assert(ctx);
	elog_assert(ctx->conf);
	elog_assert(ctx->count);
	elog_assert(ctx->parsers);
	elog_assert(spec);
	elog_assert(spec[0]);
	elog_assert(pref);
	elog_assert(pref[0]);

	struct elog_parse * parse = &ctx->parse;
	int                 ret;

	ret = ustr_parse_token_fields(spec, ':', ctx->parsers, ctx->count, ctx);
	if (ret < 0) {
		if ((ret == -ENODATA) && !parse->error)
			/*
			 * This may happen when a parser is not given a
			 * chance to run in case an empty field occurs.
			 */
			elogger_err("%s parsing error: "
			            "empty or missing specifier.\n",
			            pref);
		else
			elogger_err("%s parsing error: %s.\n",
			            pref,
			            parse->error);
		goto fini;
	}

	ret = elog_realize_parse(parse, ctx->conf);
	if (ret)
		elogger_err("%s.", parse->error);

fini:
	elog_fini_parse(parse);

	return ret;
}

#if defined(CONFIG_ELOG_STDIO)

static int __elog_nonull(1, 3)
elogger_parse_stdio_severity_spec(char * __restrict  arg,
                                  size_t             len __unused,
                                  void *  __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_stdio_severity(&ctx->parse,
	                                 (struct elog_stdio_conf *)ctx->conf,
	                                 arg);
}

static int __elog_nonull(1, 3)
elogger_parse_stdio_format_spec(char * __restrict arg,
                                size_t            len __unused,
                                void * __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_stdio_format(&ctx->parse,
	                               (struct elog_stdio_conf *)ctx->conf,
	                               arg);
}

static struct elog * __elog_nonull(1)
elogger_build_stdlog(char * __restrict spec)
{
	elog_assert(spec);

	int                                 ret;
	struct elog *                       sublog;
	static const struct elog_stdio_conf dflt = {
		.super.severity = ELOG_WARNING_SEVERITY,
		.format         = ELOG_TAG_FMT | ELOG_PID_FMT
	};

	if (spec[0]) {
		struct elog_stdio_conf             conf;
		static ustr_parse_token_fn * const parsers[] = {
			elogger_parse_stdio_severity_spec,
			elogger_parse_stdio_format_spec
		};
		struct elogger_context             ctx = {
			.conf    = (struct elog_conf *)&conf,
			.count   = stroll_array_nr(parsers),
			.parsers = parsers
		};

		elog_init_stdio_parse(&ctx.parse, &conf, &dflt);

		ret = elogger_finalize_parsing(&ctx, spec, "stdlog");
		if (ret) {
			errno = -ret;
			return NULL;
		}

		sublog = elog_create_stdio(&conf);
	}
	else
		sublog = elog_create_stdio(&dflt);

	if (sublog)
		return sublog;

	ret = errno;
	elogger_err("cannot create stdlog logger: %s (%d).",
	            strerror(ret),
	            ret);
	errno = ret;

	return NULL;
}

#define STDLOG_TOPSPEC "|<STDLOG_SPEC>"

#define STDLOG_SPEC \
"    STDLOG_SPEC   := stdlog[:<SEVERITY>[:<STD_FORMAT>]]\n"

#define STDLOG_FORMAT \
"\n" \
"    STD_FORMAT    := none|dflt|<STD_FLAGS>\n" \
"    STD_FLAGS     := <STD_FLAG>[,<STD_FLAGS>]\n" \
"    STD_FLAG      := bootime|proctime|tag|pid|severity\n"

#define STDLOG_WHERE \
"    STDLOG_SPEC -- format / redirect command standard I/O stream(s) to stderr\n" \
"                   (defaults to `stdlog:warn:pid')\n" \

#else  /* !defined(CONFIG_ELOG_STDIO) */

#define STDLOG_TOPSPEC ""
#define STDLOG_SPEC    ""
#define STDLOG_FORMAT  ""
#define STDLOG_WHERE   ""

#endif /* defined(CONFIG_ELOG_STDIO) */

#if defined(CONFIG_ELOG_SYSLOG)

static int __elog_nonull(1, 3)
elogger_parse_syslog_severity_spec(char * __restrict  arg,
                                   size_t             len __unused,
                                   void *  __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_syslog_severity(&ctx->parse,
	                                  (struct elog_syslog_conf *)ctx->conf,
	                                  arg);
}

static int __elog_nonull(1, 3)
elogger_parse_syslog_format_spec(char * __restrict arg,
                                 size_t            len __unused,
                                 void * __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_syslog_format(&ctx->parse,
	                                (struct elog_syslog_conf *)ctx->conf,
	                                arg);
}

static int __elog_nonull(1, 3)
elogger_parse_syslog_facility_spec(char * __restrict  arg,
                                   size_t             len __unused,
                                   void *  __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_syslog_facility(&ctx->parse,
	                                  (struct elog_syslog_conf *)ctx->conf,
	                                  arg);
}

static struct elog * __elog_nonull(1)
elogger_build_syslog(char * __restrict spec)
{
	elog_assert(spec);

	int                                  ret;
	struct elog *                        sublog;
	static const struct elog_syslog_conf dflt = {
		.super.severity = ELOG_WARNING_SEVERITY,
		.format         = ELOG_TAG_FMT | ELOG_PID_FMT,
		.facility       = LOG_USER
	};

	if (spec[0]) {
		struct elog_syslog_conf            conf;
		static ustr_parse_token_fn * const parsers[] = {
			elogger_parse_syslog_severity_spec,
			elogger_parse_syslog_format_spec,
			elogger_parse_syslog_facility_spec
		};
		struct elogger_context             ctx = {
			.conf    = (struct elog_conf *)&conf,
			.count   = stroll_array_nr(parsers),
			.parsers = parsers
		};

		elog_init_syslog_parse(&ctx.parse, &conf, &dflt);

		ret = elogger_finalize_parsing(&ctx, spec, "syslog");
		if (ret) {
			errno = -ret;
			return NULL;
		}

		sublog = elog_create_syslog(&conf);
	}
	else
		sublog = elog_create_syslog(&dflt);

	if (sublog)
		return sublog;

	ret = errno;
	elogger_err("cannot create syslog logger: %s (%d).",
	            strerror(ret),
	            ret);
	errno = ret;

	return NULL;
}

#define SYSLOG_TOPSPEC "|<SYSLOG_SPEC>"

#define SYSLOG_SPEC \
"    SYSLOG_SPEC   := syslog[:<SEVERITY>[:<SYSLOG_FORMAT>[:<FACILITY>]]]\n"

#define SYSLOG_FORMAT \
"\n" \
"    SYSLOG_FORMAT := none|dflt|pid\n"

#define SYSLOG_WHERE \
"    SYSLOG_SPEC -- format / redirect command standard I/O stream(s) to syslog\n" \
"                   (defaults to `syslog:warn:pid:user')\n"

#else  /* !defined(CONFIG_ELOG_SYSLOG) */

#define SYSLOG_TOPSPEC ""
#define SYSLOG_SPEC    ""
#define SYSLOG_FORMAT  ""
#define SYSLOG_WHERE   ""

#endif /* defined(CONFIG_ELOG_SYSLOG) */

#if defined(CONFIG_ELOG_MQUEUE)

static int __elog_nonull(1, 3)
elogger_parse_mqueue_name_spec(char * __restrict arg,
                               size_t            len __unused,
                               void * __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_mqueue_name(&ctx->parse,
	                              (struct elog_mqueue_conf *)ctx->conf,
	                              arg);
}

static int __elog_nonull(1, 3)
elogger_parse_mqueue_severity_spec(char * __restrict  arg,
                                   size_t             len __unused,
                                   void *  __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_mqueue_severity(&ctx->parse,
	                                  (struct elog_mqueue_conf *)ctx->conf,
	                                  arg);
}

static int __elog_nonull(1, 3)
elogger_parse_mqueue_facility_spec(char * __restrict  arg,
                                   size_t             len __unused,
                                   void *  __restrict data)
{
	elog_assert(arg);
	elog_assert(arg[0]);
	elog_assert(len);
	elog_assert(data);

	struct elogger_context * ctx = data;

	return elog_parse_mqueue_facility(&ctx->parse,
	                                  (struct elog_mqueue_conf *)ctx->conf,
	                                  arg);
}

static struct elog * __elog_nonull(1)
elogger_build_mqlog(char * __restrict spec)
{
	elog_assert(spec);

	int                                  ret;
	struct elog *                        sublog;
	static const struct elog_mqueue_conf dflt = {
		.super.severity = ELOG_NOTICE_SEVERITY,
		.facility       = LOG_LOCAL0,
		.name           = "/init"
	};

	if (spec[0]) {
		struct elog_mqueue_conf            conf;
		static ustr_parse_token_fn * const parsers[] = {
			elogger_parse_mqueue_name_spec,
			elogger_parse_mqueue_severity_spec,
			elogger_parse_mqueue_facility_spec
		};
		struct elogger_context             ctx = {
			.conf    = (struct elog_conf *)&conf,
			.count   = stroll_array_nr(parsers),
			.parsers = parsers
		};

		elog_init_mqueue_parse(&ctx.parse, &conf, &dflt);

		ret = elogger_finalize_parsing(&ctx, spec, "mqlog");
		if (ret) {
			errno = -ret;
			return NULL;
		}

		sublog = elog_create_mqueue(&conf);
	}
	else
		sublog = elog_create_mqueue(&dflt);

	if (sublog)
		return sublog;

	ret = errno;
	elogger_err("cannot create mqlog logger: %s (%d).",
	            strerror(ret),
	            ret);
	errno = ret;

	return NULL;
}

#define MQLOG_TOPSPEC "|<MQLOG_SPEC>"

#define MQLOG_SPEC \
"    MQLOG_SPEC    := mqlog[:<MQLOG_NAME>[:<SEVERITY>[:<FACILITY>]]]]\n"

#define MQLOG_FORMAT ""

#define MQLOG_WHERE \
"    MQLOG_SPEC  -- format / redirect command standard I/O stream(s) to message\n" \
"                   queue (defaults to `/init:notice:local0')\n" \
"    MQLOG_NAME  -- POSIX message queue name, including the leading `/',\n" \
"                   [2:255] bytes long string.\n"

#else /* !defined(CONFIG_ELOG_MQUEUE) */

#define MQLOG_TOPSPEC ""
#define MQLOG_SPEC    ""
#define MQLOG_FORMAT  ""
#define MQLOG_WHERE   ""

#endif /* defined(CONFIG_ELOG_MQUEUE) */

typedef struct elog *
        (elogger_build_fn)(char * __restrict spec) __elog_nonull(1);

struct elogger_builder {
	const char *       type;
	elogger_build_fn * build;
};

#define ELOGGER_INIT_BUILDER(_type, _build) \
	{ .type = _type, .build = _build }

static const struct elogger_builder * __elog_nonull(1) __pure
elogger_find_sublog_builder(const char * __restrict type)
{
	elog_assert(type);
	elog_assert(type[0]);

	unsigned int                        b;
	static const struct elogger_builder builders[] = {
#if defined(CONFIG_ELOG_STDIO)
		ELOGGER_INIT_BUILDER("stdlog", elogger_build_stdlog)
#endif /* defined(CONFIG_ELOG_STDIO) */
#if defined(CONFIG_ELOG_SYSLOG)
		, ELOGGER_INIT_BUILDER("syslog", elogger_build_syslog)
#endif /* defined(CONFIG_ELOG_SYSLOG) */
#if defined(CONFIG_ELOG_MQUEUE)
		, ELOGGER_INIT_BUILDER("mqlog",  elogger_build_mqlog),
#endif /* defined(CONFIG_ELOG_MQUEUE) */
	};

	for (b = 0; b < stroll_array_nr(builders); b++) {
		const struct elogger_builder * builder = &builders[b];

		if (!strcmp(type, builder->type))
			return builder;
	}

	elog_assert(b <= stroll_array_nr(builders));

	elogger_err("unknown '%s' logger type specified.", type);

	return NULL;
}

static int __elog_nonull(1, 2, 3)
elogger_build_pipe_redir(struct elogger_redir ** __restrict redir,
                         const char * __restrict            type,
                         char * __restrict                  spec)
{
	elog_assert(redir);
	elog_assert(type);
	elog_assert(type[0]);
	elog_assert(spec);

	const struct elogger_builder * builder;
	struct elog *                  sublog;
	int                            err;

	builder = elogger_find_sublog_builder(type);
	if (!builder)
		return -ENOENT;

	if (*redir == (struct elogger_redir *)&elogger_null) {
		elogger_err("cannot mix '%s' and 'null' loggers.", type);
		return -EINVAL;
	}

	sublog = builder->build(spec);
	if (!sublog)
		return -errno;

	if (!*redir) {
		*redir = elogger_acquire_pipe_redir();
		if (!*redir) {
			err = -errno;

			elogger_err("cannot create pipe redirect: %s (%d).",
			            strerror(-err),
			            -err);
			goto destroy;
		}
	}

	err = elog_register_multi_sublog(
		&((struct elogger_pipe_redir *)(*redir))->log, sublog);
	if (err) {
		elogger_err("cannot register logger: %s (%d).",
		            strerror(-err),
		            -err);
		goto destroy;
	}

	return 0;

destroy:
#if defined(CONFIG_ELOG_DEBUG)
	elog_destroy(sublog);
#endif /* defined(CONFIG_ELOG_DEBUG) */

	return err;
}

static struct elogger_redir * elogger_stdout;
static struct elogger_redir * elogger_stderr;

/******************************************************************************
 * Child process handling.
 ******************************************************************************/

static const char * elogger_tag = ELOG_DFLT_TAG;

static struct sigaction elogger_child_act = {
	.sa_handler = SIG_DFL,
	.sa_flags   = SA_NOCLDSTOP
};

static struct sigaction elogger_term_act = {
	.sa_handler = elogger_handle_term_sig,
	.sa_flags   = 0
};

static const struct usig_new_act elogger_sig_acts[] = {
	{ .no = SIGCHLD, .act = &elogger_child_act },
	{ .no = SIGHUP,  .act = &elogger_term_act },
	{ .no = SIGINT,  .act = &elogger_term_act },
	{ .no = SIGQUIT, .act = &elogger_term_act },
	{ .no = SIGTERM, .act = &elogger_term_act }
};

static void __elog_nonull(3, 4) __noreturn
elogger_exec_child(const struct usig_orig_act  sig_act[__restrict_arr],
                   unsigned int                sig_nr,
                   const sigset_t * __restrict sig_msk,
                   char * const                args[])
{
	elog_assert(sig_act);
	elog_assert(sig_nr);
	elog_assert(sig_msk);
	elog_assert(args);
	elog_assert(args[0]);

	if (elogger_stdout)
		if (elogger_connect_redir_child(elogger_stdout, STDOUT_FILENO))
			goto exit;

	if (elogger_stderr)
		if (elogger_connect_redir_child(elogger_stderr, STDERR_FILENO))
			goto exit;

	elogger_cleanup_fds();

	usig_restore_actions(sig_act, sig_nr);
	usig_procmask(SIG_SETMASK, sig_msk, NULL);

	/*
	 * Perform the real exec.
	 *
	 * Warning: give execve() a NULL env pointer ; this will properly work
	 *          while running onto Linux (and a few other UNIX variants) but
	 *          this is not portable !
	 */
	if (execve(args[0], args, NULL)) {
		elog_assert(errno != EFAULT);
		elog_assert(errno != ENAMETOOLONG);
	}

exit:
	_exit(EX_OSERR);
}

static int __elog_nonull(1)
elogger_spawn_child(char * const args[])
{
	int                  ret;
	sigset_t             orig_msk;
	struct usig_orig_act orig_acts[stroll_array_nr(elogger_sig_acts)];

	elogger_child_act.sa_mask = *usig_empty_msk;
	elogger_term_act.sa_mask = *usig_empty_msk;
	usig_addset(&elogger_term_act.sa_mask, SIGHUP);
	usig_addset(&elogger_term_act.sa_mask, SIGINT);
	usig_addset(&elogger_term_act.sa_mask, SIGQUIT);
	usig_addset(&elogger_term_act.sa_mask, SIGTERM);

	usig_procmask(SIG_SETMASK, usig_full_msk, &orig_msk);
	usig_setup_actions(elogger_sig_acts,
	                   orig_acts,
	                   stroll_array_nr(elogger_sig_acts));

	elogger_signo = 0;
	elogger_child = vfork();
	if (elogger_child < 0) {
		/* Fork failed. */
		ret = -errno;
		elog_assert(ret != -ENOSYS);

		elogger_err("cannot spawn child process: %s (%d).\n",
		            strerror(-ret),
		            -ret);
		goto unblock;
	}
	else if (!elogger_child)
		/* Child: elogger_exec_child() does not return. */
		elogger_exec_child(orig_acts,
		                   stroll_array_nr(orig_acts),
		                   &orig_msk,
		                   args);

	elog_setup(elogger_tag, elogger_child);

	ret = 0;

unblock:
	usig_procmask(SIG_SETMASK, &orig_msk, NULL);

	return ret;
}

static int
elogger_wait_child(void)
{
	elog_assert(elogger_child > 0);

	siginfo_t info;
	int       stat;

	while (waitid(P_PID, elogger_child, &info, WEXITED))
		elog_assert(errno == EINTR);

	elog_assert(info.si_signo == SIGCHLD);
	elog_assert(info.si_pid == elogger_child);

	switch (info.si_code) {
	case CLD_EXITED:
		stat = info.si_status;
		if (stat)
			elogger_debug("child process exited with status %d.",
			              stat);
		break;

	case CLD_KILLED:
		stat = 0x80 | info.si_status;
		elogger_debug("child process killed with signal %s (%d).",
		              strsignal(info.si_status),
		              info.si_status);
		break;

	case CLD_DUMPED:
		stat = 0x80 | info.si_status;
		elogger_debug("child process coredumped with signal %s (%d).",
		              strsignal(info.si_status),
		              info.si_status);
		break;

	default:
		elog_assert(0);
		unreachable();
	}

	if (!stat && elogger_signo)
		stat = 0x80 | elogger_signo;

	return stat;
}

/******************************************************************************
 * Main logic.
 ******************************************************************************/

#define ELOGGER_USAGE \
"Usage: %1$s [OPTIONS] <CMD>\n" \
"\n" \
"Run command redirecting and / or reformating its standard I/O streams.\n" \
"\n" \
"With OPTIONS:\n" \
"    -t|--tag    <TAG>  -- log message using tag TAG (defaults to `%1$s')\n" \
"    -o|--outlog <SPEC> -- format / redirect command's stdout\n" \
"    -e|--errlog <SPEC> -- format / redirect command's stderr\n" \
"\n" \
"    When unspecified, no format / redirection occurs.\n" \
"\n" \
"With:\n" \
"    SPEC          := null" STDLOG_TOPSPEC SYSLOG_TOPSPEC MQLOG_TOPSPEC"\n" \
STDLOG_SPEC \
SYSLOG_SPEC \
MQLOG_SPEC \
"\n" \
"    SEVERITY      := dflt|emerg|alert|crit|err|warn|notice|info|debug\n" \
"    FACILITY      := dflt|auth|authpriv|cron|daemon|ftp|lpr|mail|news|\n" \
"                     syslog|user|uucp|local0|local1|local2|local3|local4|\n" \
"                     local5|local6|local7\n" \
STDLOG_FORMAT \
SYSLOG_FORMAT \
MQLOG_FORMAT \
"\n" \
"Where:\n" \
"    CMD         -- command to spawn\n" \
"    null        -- disable corresponding command output\n" \
"    TAG         -- logging message tag, [1:31] bytes long string\n" \
STDLOG_WHERE \
SYSLOG_WHERE \
MQLOG_WHERE

static void __elog_nonull(1)
elogger_usage(FILE * stdio)
{
	fprintf(stdio, ELOGGER_USAGE, program_invocation_short_name);
}

static int __elog_nonull(1, 2)
elogger_build_redir(struct elogger_redir ** __restrict redir,
                    char * __restrict                  spec)
{
	elog_assert(redir);
	elog_assert(spec);
	elog_assert(spec[0]);

	if (strcmp(spec, "null")) {
		char * sep;

		sep = strchrnul(spec, ':');
		if (*sep) {
			*sep++ = '\0';
			if (!*sep) {
				elogger_err(
					"logger parsing error: "
					"missing '%s' logger specification.",
					spec);
				return -EINVAL;
			}
		}

		return elogger_build_pipe_redir(redir, spec, sep);
	}

	return elogger_build_null_redir(redir);
}

static int __elog_nonull(2)
elogger_build_from_cmdln(int argc, char * const argv[])
{
	elog_assert(argc);
	elog_assert(argv);
	elog_assert(argv[0]);
	elog_assert(!argv[argc]);

	int ret;

	while (true) {
		static const struct option opts[] = {
			{ "tag",    required_argument, NULL, 't' },
			{ "outlog", required_argument, NULL, 'o' },
			{ "errlog", required_argument, NULL, 'e' },
			{ "help",   no_argument,       NULL, 'h' },
			{ NULL,     0,                 NULL,  0 }
		};

		ret = getopt_long(argc, argv, ":t:o:e:h", opts, NULL);
		if (ret < 0)
			/* End of command line option parsing. */
			break;

		switch (ret) {
		case 't':
			if (!elog_is_tag_valid(optarg)) {
				elogger_err("invalid tag '%s' specified.\n",
				            optarg);
				goto usage;
			}

			ret = 0;
			elogger_tag = optarg;
			break;

		case 'o':
			if (elogger_build_redir(&elogger_stdout, optarg))
			    return -1;
			ret = 0;
			break;

		case 'e':
			if (elogger_build_redir(&elogger_stderr, optarg))
				return -1;
			ret = 0;
			break;

		case 'h':
			elogger_usage(stdout);
			return 0;

		case ':':
			elogger_err("option '%s' requires an argument.\n",
			            argv[optind - 1]);
			goto usage;

		case '?':
			elogger_err("unrecognized option '%s'.\n",
			            argv[optind - 1]);
			goto usage;

		default:
			elogger_err("unexpected option parsing error.");
			return -1;
		}

		if (ret)
			goto usage;
	}

	if (optind >= argc) {
		elogger_err("missing argument(s).\n");
		goto usage;
	}

	return optind;

usage:
	elogger_usage(stderr);

	return -1;
}

int
main(int argc, char * const argv[])
{
	int ret;
	int shut = 0;

	elogger_cleanup_fds();

	ret = elogger_build_from_cmdln(argc, argv);
	if (ret <= 0)
		goto out;

	ret = elogger_spawn_child(&argv[ret]);
	if (ret)
		goto out;

	if (elogger_stdout)
		elogger_start_redir(elogger_stdout);
	if (elogger_stderr)
		elogger_start_redir(elogger_stderr);

	shut = elogger_poller_refcnt;
	while (shut) {
		ret = upoll_process(&elogger_poller, -1);
		if (ret == -ESHUTDOWN)
			shut--;
		else if (ret == -EINTR)
			/*
			 * FIXME: implement a timeout strategy to prevent from
			 * waiting for a buggy child forever ??
			 */
			;
		else
			elog_assert(!ret);
	}

	ret = elogger_wait_child();

out:
	if (elogger_stderr)
		elogger_release_redir(elogger_stderr);
	if (elogger_stdout)
		elogger_release_redir(elogger_stdout);

	return (!ret) ? EXIT_SUCCESS : EXIT_FAILURE;
}
