/* SPDX-License-Identifier: GPL-2.0 */
#ifndef foomainhfoo
#define foomainhfoo

#include "list.h"

enum states {
	READY,
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
	bool pending_changes;
	bool daemonize;
	FILE *log_file;
	const char *log_file_path;
	const char *command;
	unsigned monitored_netdevs_count;
	char **to_monitor_netdevs;
	char to_monitor_netdevs_count;
	struct list_head netdevs;
};

extern struct config config;

#endif
