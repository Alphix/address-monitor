/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <systemd/sd-daemon.h>

#include "config.h"
#include "utils.h"
#include "main.h"

struct config config = {
	.state = RELOADING,
	.pending_changes = false,
	.daemonize = false,
	.log_file = NULL,
	.log_file_path = NULL,
	.command = "/usr/local/sbin/address-monitor-helper",
	.monitored_netdevs_count = 0,
	.to_monitor_netdevs = NULL,
	.to_monitor_netdevs_count = 0,
	.netdevs = LIST_HEAD_INIT(config.netdevs),
};

static void
update_ready_state()
{
	if (config.state != READY)
		return;

	if (config.to_monitor_netdevs_count > 0) {
		sd_notifyf(0,
			   "READY=1\n"
			   "STATUS=Running, %u/%u netdevs being monitored\n",
			   config.monitored_netdevs_count,
			   config.to_monitor_netdevs_count);
		verbose("State: Running, %u/%u netdevs being monitored",
			config.monitored_netdevs_count,
			config.to_monitor_netdevs_count);
	} else {
		sd_notifyf(0,
			   "READY=1\n"
			   "STATUS=Running, %u netdevs being monitored\n",
			   config.monitored_netdevs_count);
		verbose("State: Running, %u netdevs being monitored",
			config.monitored_netdevs_count);
	}
}

static void
set_state(enum states state, const char *reason)
{
	if (config.state == state)
		return;

	config.state = state;

	switch (state) {
	case READY:
		update_ready_state();
		break;
	case RELOADING:
		if (reason) {
			sd_notifyf(0,
				   "RELOADING=1\n"
				   "STATUS=Reloading (%s)\n", reason);
			verbose("State: Reloading (%s)", reason);
		} else {
			sd_notifyf(0,
				   "RELOADING=1\n"
				   "STATUS=Reloading\n");
			verbose("State: Reloading");
		}
		break;
	case STOPPING:
		if (reason) {
			sd_notifyf(0,
				   "STOPPING=1\n"
				   "STATUS=Stopping (%s)\n", reason);
			verbose("State: Stopping (%s)", reason);
		} else {
			sd_notifyf(0,
				   "STOPPING=1\n"
				   "STATUS=Stopping\n");
			verbose("State: Stopping");
		}
		break;
	}
}

static int
netdev_del_addr(int index, const char *addr)
{
	struct netdev *dev;
	struct netdev_addr *netdev_addr, *found = NULL;

	list_for_each_entry(dev, &config.netdevs, list) {
		if (dev->index != index)
			continue;

		if (!dev->monitored)
			continue;

		list_for_each_entry(netdev_addr, &dev->addrs, list) {
			if (streq(netdev_addr->addr, addr)) {
				found = netdev_addr;
				break;
			}
		}

		if (!found) {
			verbose("Unknown address deleted from interface %s (%i): %s",
				dev->name, dev->index, addr);
			return -1;
		}

		list_del(&found->list);
		verbose("Address deleted from interface %s (%i): %s",
			dev->name, dev->index, addr);

		config.pending_changes = true;
		return 0;
	}

	verbose("Address deleted from unknown interface %i: %s", index, addr);
	return -1;
}

static int
netdev_add_addr(int index, const char *addr)
{
	struct netdev *dev;
	struct netdev_addr *netdev_addr;

	list_for_each_entry(dev, &config.netdevs, list) {
		if (dev->index != index)
			continue;

		if (!dev->monitored)
			return 0;

		list_for_each_entry(netdev_addr, &dev->addrs, list) {
			if (streq(addr, netdev_addr->addr)) {
				debug("Known address refreshed for interface %s (%i): %s",
				      dev->name, dev->index, addr);
				return 0;
			}
		}
	
		netdev_addr = malloc(sizeof(*netdev_addr));
		netdev_addr->addr = strdup(addr);
		if (!netdev_addr->addr) {
			error("strdup addr (%m");
			return -1;
		}

		list_add(&netdev_addr->list, &dev->addrs);
		verbose("New address added to interface %s (%i): %s",
			dev->name, dev->index, addr);
		config.pending_changes = true;
		return 0;
	}

	verbose("Address added to unknown interface %i: %s", index, addr);
	return -1;
}

static unsigned
netdev_del(int index)
{
	struct netdev *dev, *tdev;
	struct netdev_addr *netdev_addr, *taddr;
	unsigned r = 0;

	list_for_each_entry_safe(dev, tdev, &config.netdevs, list) {
		if (dev->index != index)
			continue;

		list_for_each_entry_safe(netdev_addr, taddr, &dev->addrs, list) {
			list_del(&netdev_addr->list);
			free(netdev_addr->addr);
			free(netdev_addr);
		}

		verbose("Deleted interface %s, index %i (%smonitored)",
			dev->name, dev->index, dev->monitored ? "" : "not ");

		list_del(&dev->list);
		if (dev->monitored)
			config.monitored_netdevs_count--;
		free(dev->name);
		free(dev);
		r++;
	}

	if (r > 0)
		update_ready_state();
	config.pending_changes = true;
	return r;
}

static unsigned
netdev_del_all()
{
	struct netdev *dev, *tmp;
	unsigned r = 0;

	list_for_each_entry_safe(dev, tmp, &config.netdevs, list) {
		list_del(&dev->list);
		if (dev->monitored)
			config.monitored_netdevs_count--;
		free(dev->name);
		free(dev);
		r++;
	}

	config.pending_changes = true;
	return r;
}

static int
netdev_add(int index, const char *name)
{
	struct netdev *dev;
	bool monitored = config.to_monitor_netdevs ? false : true;

	if (config.to_monitor_netdevs && name) {
		char **tmp;
		for (tmp = config.to_monitor_netdevs; *tmp; tmp++) {
			if (streq(*tmp, name)) {
				monitored = true;
				break;
			}
		}
	}

	list_for_each_entry(dev, &config.netdevs, list) {
		if (dev->index != index)
			continue;
		if (empty_str(dev->name) && !empty_str(name))
			dev->name = strdup(name);
		dev->monitored = monitored;
		return 0;
	}

	dev = malloc(sizeof(*dev));
	if (!dev) {
		error("malloc (%m)");
		return -1;
	}

	INIT_LIST_HEAD(&dev->addrs);
	dev->name = strdup(name);
	if (!dev->name) {
		error("strdup (%m)");
		free(dev);
		return -1;
	}

	dev->index = index;
	dev->monitored = monitored;
	list_add(&dev->list, &config.netdevs);
	if (dev->monitored) {
		config.monitored_netdevs_count++;
		update_ready_state();
	}

	verbose("Added interface %s, index %i (%smonitored)",
		dev->name, dev->index, dev->monitored ? "" : "not ");
	return 0;
}

/*
 * Return values:
 * < 0 = error
 *   0 = done
 * > 0 = read again
 */
static int
netlink_read_once(int nfd)
{
	char buffer[32 * 1024];
	ssize_t r;

	r = recv(nfd, buffer, sizeof(buffer), 0);
	if (r == 0) {
		return 0;
	} else if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		error("netlink recv (%m)");
		return -1;
	} else if ((size_t)r >= sizeof(buffer)) {
		error("netlink buffer overflow (%zi)", r);
		return -1;
	}

	debug("Read %zi bytes from netlink", r);
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

	if (nlh->nlmsg_flags & MSG_TRUNC)
		return -1;

	for (int len = r; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rth;
		int if_index;

		switch (nlh->nlmsg_type) {
		case RTM_NEWLINK:
			_fallthrough_;
		case RTM_DELLINK:
			struct ifinfomsg *ifi = NLMSG_DATA(nlh);
			char if_name[128];

			if_index = ifi->ifi_index;
			rth = IFLA_RTA(ifi);

			for (int rtl = IFLA_PAYLOAD(nlh); RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
				if (rth->rta_type == IFLA_IFNAME)
					strcpy(if_name, RTA_DATA(rth));
			}

			if (nlh->nlmsg_type == RTM_NEWLINK)
				netdev_add(if_index, if_name);
			else
				netdev_del(if_index);
			break;

		case RTM_NEWADDR:
			_fallthrough_;
		case RTM_DELADDR:
			struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
			char if_addr[1024];

			if (ifa->ifa_flags & IFA_F_TENTATIVE)
				continue;

			if_index = ifa->ifa_index;
			rth = IFA_RTA(ifa);

			for (int rtl = IFA_PAYLOAD(nlh); RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
				switch (ifa->ifa_family) {
				case AF_INET:
					if (rth->rta_type != IFA_LOCAL)
						continue;
					if (!inet_ntop(ifa->ifa_family, RTA_DATA(rth), if_addr, sizeof(if_addr)))
						return -1;
					break;
				case AF_INET6:
					if (rth->rta_type != IFA_ADDRESS)
						continue;
					if (!inet_ntop(ifa->ifa_family, RTA_DATA(rth), if_addr, sizeof(if_addr)))
						return -1;

					size_t offset = strlen(if_addr);
					size_t remain = sizeof(if_addr) - offset;
					int len = snprintf(if_addr + offset, remain, "/%" PRIu8, ifa->ifa_prefixlen);
					if (len < 1 || (unsigned)len >= remain)
						return -1;
					break;
				default:
					continue;
				}

				if (nlh->nlmsg_type == RTM_NEWADDR)
					netdev_add_addr(if_index, if_addr);
				else
					netdev_del_addr(if_index, if_addr);
			}
			break;

		case NLMSG_DONE:
			break;

		case NLMSG_ERROR:
			verbose("Netlink error received");
			return -1;

		default:
			debug("Unhandled netlink type: %i", nlh->nlmsg_type);
			break;
		}
	}

	return 1;
}

static int
netlink_read(int nfd)
{
	int r;

	while (true) {
		r = netlink_read_once(nfd);
		if (r <= 0)
			break;
	}

	if (r < 0)
		set_state(RELOADING, "netlink read");
	return r;
}

static int
netlink_get_names(int nfd)
{
	ssize_t r;
	size_t if_msglen = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	struct {
		struct nlmsghdr nlhdr;
		struct ifinfomsg infomsg;
	} if_msg = {
		.nlhdr.nlmsg_len = if_msglen,
		.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
		.nlhdr.nlmsg_type = RTM_GETLINK,
		.infomsg.ifi_family = AF_UNSPEC,
	};
	size_t addr_msglen = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	struct {
		struct nlmsghdr nlhdr;
		struct ifaddrmsg addrmsg;
	} addr_msg = {
		.nlhdr.nlmsg_len = addr_msglen,
		.nlhdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT,
		.nlhdr.nlmsg_type = RTM_GETADDR,
		.addrmsg.ifa_family = AF_UNSPEC,
	};

	r = send(nfd, &if_msg, if_msglen, 0);
	if (r < 0 || (size_t)r != if_msglen) {
		error("netlink send (%m)");
		return r;
	}

	r = netlink_read(nfd);
	if (r < 0)
		return r;

	r = send(nfd, &addr_msg, addr_msglen, 0);
	if (r < 0 || (size_t)r != addr_msglen) {
		error("netlink send (%m)");
		return r;
	}

	r = netlink_read(nfd);
	if (r < 0)
		return r;

	return 0;
}

static int
netlink_init()
{
	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
	};
	int nfd;

	nfd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (nfd < 0) {
		error("netlink socket (%m)");
		goto out;
	}

	if (bind(nfd, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
		error("bind (%m)");
		close(nfd);
		nfd = -1;
		goto out;
	}

	if (netlink_get_names(nfd) < 0) {
		close(nfd);
		nfd = -1;
	}

out:
	if (nfd < 0)
		set_state(RELOADING, "netlink_init");
	return nfd;
}

/*
 * Return values:
 * < 0 = error
 *   0 = done
 * > 0 = read again
 */
static int
timerfd_read_once(int tfd)
{
	uint64_t exp;
	ssize_t r;

	r = read(tfd, &exp, sizeof(exp));
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		error("timerfd read (%m)");
		return -1;
	} else if ((size_t)r != sizeof(exp)) {
		error("timerfd weird read size: %zi", r);
		return -1;
	}

	debug("Timerfd expiries: %" PRIu64, exp);
	return 1;
}

static int
timerfd_read(int tfd)
{
	int r;

	while (true) {
		r = timerfd_read_once(tfd);
		if (r <= 0)
			break;
	}

	if (r < 0)
		set_state(RELOADING, "timerfd_read");

	return r;
}

static int
timerfd_arm(int tfd)
{
	struct itimerspec new_value = {
		.it_value.tv_sec = 10,
		.it_value.tv_nsec = 0,
		.it_interval.tv_sec = 0,
		.it_interval.tv_nsec = 0,
	};
	struct itimerspec old_value;
	int r;

	r = timerfd_settime(tfd, 0, &new_value, &old_value);
	if (r < 0) {
		error("timerfd_settime (%m)");
		set_state(RELOADING, "timerfd_settime");
	}

	return r;
}

static int
timerfd_init()
{
	int tfd;

	tfd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (tfd < 0) {
		error("timerfd_create (%m)");
		set_state(RELOADING, "timerfd_create");
	}

	return tfd;
}

/*
 * Return values:
 * < 0 = error
 *   0 = done
 * > 0 = read again
 */
static int
signalfd_read_once(int sfd)
{
	struct signalfd_siginfo sig;
	ssize_t r;

	r = read(sfd, &sig, sizeof(sig));
	if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		error("signalfd read (%m)");
		set_state(RELOADING, "signalfd_read");
		return -1;
	} else if ((size_t)r != sizeof(sig)) {
		error("signalfd weird read size: %zi", r);
		set_state(RELOADING, "signalfd_read");
		return -1;
	}

	debug("Received signal (%u): %s", (unsigned)sig.ssi_signo, strsignal(sig.ssi_signo));
	switch (sig.ssi_signo) {
	case SIGINT:
		_fallthrough_;
	case SIGTERM:
		set_state(STOPPING, "SIGTERM");
		r = 0;
		break;
	case SIGHUP:
		set_state(RELOADING, "SIGHUP");
		r = 0;
		break;
	case SIGUSR1:
		struct netdev *dev;
		info("Dumping list of known netdevs:");
		list_for_each_entry(dev, &config.netdevs, list)
			info("\tnetdev: index %i, name %s", dev->index, dev->name);
		_fallthrough_;
	default:
		r = 1;
		break;
	}

	return r;
}

static int
signalfd_read(int sfd)
{
	int r;

	while (true) {
		r = signalfd_read_once(sfd);
		if (r <= 0)
			break;
	}

	return r;
}

static int
signalfd_init()
{
	sigset_t sigset;
	int r;

	r = sigfillset(&sigset);
	if (r < 0) {
		error("sigfillset (%m)");
		goto out;
	}

	r = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (r < 0) {
		error("sigprocmask (%m)");
		goto out;
	}

	r = signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
	if (r < 0)
		error("signalfd (%m)");

out:
	if (r < 0)
		set_state(RELOADING, "signalfd_init");
	return r;
}

/*
 * Return values:
 * < 0 = error
 *   0 = done
 * > 0 = read again
 */
static int
childfd_wait_once(int *cfd)
{
	siginfo_t info;
	int r;

	if (*cfd < 0)
		return 0;

	info.si_pid = 0;
	r = waitid(P_PIDFD, *cfd, &info, WEXITED | WSTOPPED | WCONTINUED | WNOHANG);
	if (r < 0) {
		if (errno == EAGAIN)
			return 0;
		else if (errno == EINTR)
			return 1;

		error("waitid (%m)");
		set_state(RELOADING, "waitid");
		close(*cfd);
		*cfd = -1;
		return -1;
	}

	if (info.si_pid == 0)
		return 0;

	switch (info.si_code) {
	case CLD_EXITED:
		if (info.si_status == 0)
			verbose("Child command finished successfully");
		else
			info("Child command exited with error: %i", info.si_status);
		break;
	case CLD_DUMPED:
		_fallthrough_;
	case CLD_KILLED:
		verbose("Child command killed with signal: %i", info.si_status);
		break;
	case CLD_STOPPED:
		debug("Child stopped, signal: %i", info.si_status);
		goto out;
	case CLD_CONTINUED:
		debug("Child continued, signal: %i", info.si_status);
		goto out;
	case CLD_TRAPPED:
		debug("Traced child has trapped, signal: %i", info.si_status);
		goto out;
	default:
		debug("Unknown child state: %i", info.si_code);
		goto out;
	}

	close(*cfd);
	*cfd = -1;
out:
	return 0;
}

static int
childfd_wait(int *cfd)
{
	int r;

	while (true) {
		r = childfd_wait_once(cfd);
		if (r <= 0)
			break;
	}

	return r;
}

static void
childfd_kill(int *cfd)
{
	childfd_wait(cfd);
	if (*cfd < 0)
		return;

	sleep(5);
	childfd_wait(cfd);
	if (*cfd < 0)
		return;

	sys_pidfd_send_signal(*cfd, SIGTERM);
	sleep(5);
	childfd_wait(cfd);
	if (*cfd < 0)
		return;

	sys_pidfd_send_signal(*cfd, SIGKILL);
	sleep(5);
	childfd_wait(cfd);
	if (*cfd < 0)
		return;

	close(*cfd);
	*cfd = -1;
}

static int
childfd_init(const char *path)
{
	int pidfd;
	struct clone_args args = {
		.pidfd = (__u64)(uintptr_t)&pidfd,
		.flags = CLONE_PIDFD | CLONE_CLEAR_SIGHAND,
		/* setting exit_signal to zero breaks waitid */
		.exit_signal = SIGCHLD,
	};
	pid_t pid;

	pid = sys_clone3(&args);
	if (pid < 0) {
		error("clone3 (%m)");
		set_state(RELOADING, "clone3");
		return -1;
	} else if (pid == 0) {
		/* Child */
		execl(path, path, NULL);
		error("execl %s: %m", path);
		fflush(stdout);
		fflush(stderr);
		exit(EXIT_FAILURE);
	} else {
		/* Parent */
		verbose("Launched command %s, pid %d, pidfd %d", path, pid, pidfd);
		config.pending_changes = false;
		return pidfd;
	}
}

static int
epoll_add(int efd, int fd)
{
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET,
		.data.fd = fd,
	};
	int r;

	if (fd < 0)
		return -1;

	r = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (r < 0) {
		error("epoll_ctl (%m)");
		set_state(RELOADING, "epoll_ctl");
	}
	return r;
}

static int
event_loop()
{
	set_state(READY, NULL);

	_cleanup_close_ int efd = -1;
	_cleanup_close_ int sfd = signalfd_init();
	_cleanup_close_ int nfd = netlink_init();
	_cleanup_close_ int tfd = timerfd_init();
	int cfd = -1;

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0)
		die("epoll_create (%m)");
	
	epoll_add(efd, sfd);
	epoll_add(efd, nfd);
	epoll_add(efd, tfd);

	debug("Epoll ready: efd %i sfd %i nfd %i tfd %i", efd, sfd, nfd, tfd);

	while (config.state == READY) {
		struct epoll_event ev;
		int r;

		if (config.pending_changes)
			if (timerfd_arm(tfd) < 0)
				break;

		r = epoll_wait(efd, &ev, 1, -1);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			error("epoll_wait (%m)");
			set_state(RELOADING, "epoll_wait");
			break;
		} else if (r == 0) {
			error("Unexpected epoll_wait return value (0)");
			set_state(RELOADING, "epoll_wait");
			break;
		} else if (ev.data.fd < 0) {
			error("Unexpected epoll_wait return fd: %i", ev.data.fd);
			set_state(RELOADING, "epoll_wait");
			break;
		} else if (ev.events != EPOLLIN) {
			error("Unexpected epoll_wait return event: 0x%08" PRIx32, ev.events);
			set_state(RELOADING, "epoll_wait");
			break;
		}

		debug("Received event on fd %i", ev.data.fd);

		if (ev.data.fd == nfd) {
			netlink_read(nfd);

		} else if (ev.data.fd == tfd) {
			if (timerfd_read(tfd) < 0)
				break;

			cfd = childfd_init(config.command);
			if (cfd < 0)
				break;

			epoll_add(efd, cfd);

		} else if (ev.data.fd == sfd) {
			signalfd_read(sfd);

		} else if (ev.data.fd == cfd) {
			childfd_wait(&cfd);
		}
	}

	childfd_kill(&cfd);
	netdev_del_all();
	return 0;
}

_noreturn_ static void
usage(bool invalid)
{
	if (invalid)
		info("Invalid option(s)");

	info("Usage: %s [OPTION...] [IFNAME...]\n"
	       "\n"
	       "Valid options:\n"
	       "  -c, --command=PATH\texecute the command at PATH on address change\n"
	       "  -l, --logfile=FILE\tlog to FILE instead of stderr\n"
	       "  -h, --help\t\tprint this information\n"
	       "  -v, --verbose\t\tenable verbose logging\n"
	       "  -d, --debug\t\tenable debug logging\n"
	       "\n"
	       "When IFNAME(s) are provided, monitor the given interfaces.\n"
	       "Otherwise, all interfaces are monitored.\n",
	       program_invocation_short_name);

	exit(invalid ? EXIT_FAILURE : EXIT_SUCCESS);
}

static void
config_init(int argc, char **argv)
{
	int c;

	while (true) {
		int option_index = 0;
		static struct option long_options[] = {
			{ "command",	required_argument,	0, 'c' },
			{ "logfile",	required_argument,	0, 'l' },
			{ "help",	no_argument,		0, 'h' },
			{ "verbose",	no_argument,		0, 'v' },
			{ "debug",	no_argument,		0, 'd' },
			{ 0,		0,			0,  0  },
		};

		c = getopt_long(argc, argv, ":c:l:hvd", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			config.command = optarg;
			break;
		case 'l':
			config.log_file_path = optarg;
			break;
		case 'v':
			debug_mask |= DBG_VERBOSE;
			break;
		case 'd':
			debug_mask |= DBG_DEBUG | DBG_VERBOSE;
			break;
		case 'h':
			usage(false);
			break;
		default:
			usage(true);
			break;
		}
	}

	if (optind < argc) {
		config.to_monitor_netdevs = &argv[optind];
		config.to_monitor_netdevs_count = argc - optind;
	}

	if (config.log_file_path) {
		FILE *log_file = fopen(config.log_file_path, "ae");
		if (!log_file)
			die("fopen(%s) failed: %m", config.log_file_path);
		config.log_file = log_file;
	}
}

int
main(int argc, char **argv)
{
	assert_die(argc > 0 && argv, "invalid arguments");

	sd_notifyf(0, "MAINPID=%lu", (unsigned long)getpid());

	config_init(argc, argv);

	while (config.state != STOPPING) {
		config.pending_changes = true;
		event_loop();
	}

	if (config.log_file) {
		fflush(config.log_file);
		fclose(config.log_file);
		config.log_file = NULL;
	}
	fflush(stdout);
	fflush(stderr);
	exit(EXIT_SUCCESS);
}
