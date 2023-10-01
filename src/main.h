/* SPDX-License-Identifier: GPL-2.0 */
#ifndef foomainhfoo
#define foomainhfoo

#pragma GCC diagnostic ignored "-Wpadded"

#include "list.h"

enum states {
	READY,
	CHANGES_PENDING,
	RELOADING,
	STOPPING,
};

struct netdev_addr {
	char *addr;
	struct list_head list;
};

struct netdev {
	int index;
	char *name;
	bool monitored;
	struct list_head addrs;
	struct list_head list;
};

struct config {
	enum states state;
	unsigned failed_helper_attempts;
	bool daemonize;
	FILE *log_file;
	const char *log_file_path;
	const char *command;
	unsigned monitored_netdevs_count;
	char **to_monitor_netdevs;
	unsigned to_monitor_netdevs_count;
	struct list_head netdevs;
	time_t wait_time;
};

extern struct config config;

#endif
