/* SPDX-License-Identifier: GPL-2.0 */
#ifndef fooutilshfoo
#define fooutilshfoo

#define _unused_	__attribute__((__unused__))
#define _noreturn_	__attribute__((__noreturn__))
#define _fallthrough_	__attribute__((__fallthrough__))

#include <stdbool.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

#include "list.h"

enum debug_lvl {
	DBG_ERROR	= (0x1 << 1),
	DBG_INFO	= (0x1 << 2),
	DBG_VERBOSE	= (0x1 << 3),
	DBG_DEBUG	= (0x1 << 4),
};

extern unsigned debug_mask;

static inline bool debug_enabled(enum debug_lvl lvl)
{
	return !!(lvl & debug_mask);
}

#define __ifdebug(lvl, fmt, ...)                                               \
	do {                                                                   \
		if (debug_enabled((lvl)))                                      \
			__debug((lvl), fmt "\n"__VA_OPT__(, )__VA_ARGS__);     \
	} while (0)

#define debug(fmt, ...)                                                        \
	__ifdebug(DBG_DEBUG, "%s:%s:%i: " fmt, __FILE__, __func__,             \
		  __LINE__ __VA_OPT__(, ) __VA_ARGS__)
#define verbose(fmt, ...) __ifdebug(DBG_VERBOSE, fmt, __VA_ARGS__)
#define info(fmt, ...)	  __ifdebug(DBG_INFO, fmt, __VA_ARGS__)
#define error(fmt, ...)                                                        \
	__ifdebug(DBG_ERROR, "%s:%s:%i: " fmt, __FILE__, __func__,             \
		  __LINE__ __VA_OPT__(, ) __VA_ARGS__)

#define die(fmt, ...)                                                          \
	__die("%s:%s:%i: " fmt "\n", __FILE__, __func__,                       \
	      __LINE__ __VA_OPT__(, ) __VA_ARGS__)

#define assert_log(expr, msg)                                                  \
	((expr) ? (true) :                                                     \
			(__debug(DBG_ERROR,                                    \
			   "%s:%s:%i: assertion \"" msg "\" failed\n",         \
			   __FILE__, __func__, __LINE__),                      \
		   false))

#define assert_return(expr, ...)                                               \
	do {                                                                   \
		if (!assert_log(expr, #expr))                                  \
			return __VA_ARGS__;                                    \
	} while (0)

#define assert_return_silent(expr, ...)                                        \
	do {                                                                   \
		if (!(expr))                                                   \
			return __VA_ARGS__;                                    \
	} while (0)

#define assert_die(expr, msg)                                                  \
	do {                                                                   \
		if (!assert_log(expr, #expr))                                  \
			die(msg);                                              \
	} while (0)

void __debug(enum debug_lvl lvl, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

_noreturn_ void __die(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));

static inline bool empty_str(const char *str)
{
	if (!str || str[0] == '\0')
		return true;
	else
		return false;
}

static inline bool streq(const char *a, const char *b)
{
	return strcmp(a, b) == 0;
}

static inline bool strcaseeq(const char *a, const char *b)
{
	return strcasecmp(a, b) == 0;
}

static inline long sys_pidfd_send_signal(int pidfd, int signal)
{
	return syscall(SYS_pidfd_send_signal, pidfd, signal, NULL, 0);
}

static inline pid_t sys_clone3(struct clone_args *args)
{
	return (pid_t)syscall(SYS_clone3, args, sizeof(struct clone_args));
}

#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void closep(int *fd)
{
	if (fd && *fd >= 0)
		close(*fd);
}
#define _cleanup_close_ _cleanup_(closep)

#endif
