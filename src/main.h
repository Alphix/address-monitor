/* SPDX-License-Identifier: GPL-2.0 */
#ifndef foomainhfoo
#define foomainhfoo

#include "list.h"

enum states {
	READY,
	RELOADING,
	STOPPING,
};

struct netdev {
	int index;
	char *name;
	bool monitored;
	struct list_head list;
};

struct config {
	enum states state;
	bool pending_changes;
	bool daemonize;
	FILE *log_file;
	const char *log_file_path;
	unsigned monitored_netdevs_count;
	char **to_monitor_netdevs;
	char to_monitor_netdevs_count;
};

extern struct config config;

#endif
