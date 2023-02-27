/* SPDX-License-Identifier: GPL-2.0 */
#ifndef fooutilshfoo
#define fooutilshfoo

#define _unused_	__attribute__((__unused__))
#define _noreturn_	__attribute__((__noreturn__))
#define _fallthrough_	__attribute__((__fallthrough__))

#include "list.h"

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

static inline int sys_pidfd_send_signal(int pidfd, int signal)
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
