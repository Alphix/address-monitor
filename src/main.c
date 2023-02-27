/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sched.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

#include "config.h"
#include "utils.h"

int quit = 0;

LIST_HEAD(netdevs);

struct netdev {
	int index;
	char *name;
	bool monitored;
	struct list_head list;
};

static int
netdev_add(int index, const char *name)
{
	struct netdev *dev;

	list_for_each_entry(dev, &netdevs, list) {
		if (dev->index != index)
			continue;
		if (empty_str(dev->name) && !empty_str(name))
			dev->name = strdup(name);
		return 0;
	}

	dev = malloc(sizeof(*dev));
	dev->index = index;
	dev->name = strdup(name);
	dev->monitored = true;
	list_add(&dev->list, &netdevs);
	return 0;
}

static int
netdev_add_addr(int index, const char *addr)
{
	struct netdev *dev;

	list_for_each_entry(dev, &netdevs, list) {
		if (dev->index != index)
			continue;
		printf("Address added to interface %s (%i): %s\n",
		       dev->name, dev->index, addr);
		return 0;
	}

	printf("Address added to unknown interface %i: %s\n", index, addr);
	return -1;
}

static unsigned
netdev_del(int index)
{
	struct netdev *dev, *tmp;
	unsigned ret = 0;

	list_for_each_entry_safe(dev, tmp, &netdevs, list) {
		if (dev->index != index)
			continue;
		list_del(&dev->list);
		free(dev->name);
		free(dev);
		ret++;
	}

	return ret;
}

static unsigned
netdev_del_all()
{
	struct netdev *dev, *tmp;
	unsigned ret = 0;

	list_for_each_entry_safe(dev, tmp, &netdevs, list) {
		list_del(&dev->list);
		free(dev->name);
		free(dev);
		ret++;
	}

	return ret;
}

static int
netdev_del_addr(int index, const char *addr)
{
	struct netdev *dev;

	list_for_each_entry(dev, &netdevs, list) {
		if (dev->index != index)
			continue;
		printf("Address deleted from interface %s (%i): %s\n",
		       dev->name, dev->index, addr);
		return 0;
	}

	printf("Address deleted from unknown interface %i: %s\n", index, addr);
	return -1;
}

static int
setup_timerfd()
{
	int fd;

	fd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		perror("timerfd_create");
		return -1;
	}

	return fd;
}

static int
arm_timerfd(int tfd)
{
	struct itimerspec new_value;
	struct itimerspec old_value;

	new_value.it_value.tv_sec = 10;
	new_value.it_value.tv_nsec = 0;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = 0;

	timerfd_settime(tfd, 0, &new_value, &old_value);
	return 0;
}

static int
read_timerfd(int tfd)
{
	uint64_t exp;
	ssize_t ret;

	ret = read(tfd, &exp, sizeof(exp));
	if (ret != sizeof(exp))
		perror("read");
	else
		printf("Timer expiry: %" PRIu64 "\n", exp);
	return 0;
}

static void
get_linknames(int sock)
{
	// Our message will be a header followed by a link payload
	struct {
	    struct nlmsghdr nlhdr;
	    struct ifinfomsg infomsg;
	} msg;

	size_t msglen = NLMSG_LENGTH(sizeof(struct ifinfomsg));

	// Fill in the message
	// NLM_F_REQUEST means we are asking the kernel for data
	// NLM_F_ROOT means provide all the addresses
	// RTM_GETLINK means we want link information
	// AF_UNSPEC means any kind of link
	memset(&msg, 0, sizeof(msg));
	msg.nlhdr.nlmsg_len    = msglen;
	msg.nlhdr.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ROOT;
	msg.nlhdr.nlmsg_type   = RTM_GETLINK;
	msg.infomsg.ifi_family = AF_UNSPEC;

	ssize_t ret;

	ret = send(sock, &msg, msglen, 0);
	if (ret < 0 || (size_t)ret != msglen) {
		fprintf(stderr, "Error sending netlink msg\n");
	}
}

static int
setup_netlinkfd()
{
	int fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);

	if (fd == -1) {
		perror("socket");
		return 1;
	}

	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
	};

	if (bind(fd, (struct sockaddr *)&snl, sizeof(snl)) == -1) {
		perror("bind");
		return 1;
	}

	get_linknames(fd);

	return fd;
}

/*
 * Return values:
 * < 0 = error
 *   0 = done
 * > 0 = read again
 */
static int
read_netlink_once(int fd)
{
	char buffer[16 * 1024];
	ssize_t ret = recv(fd, buffer, sizeof(buffer), 0);

	if (ret == 0) {
		return 0;
	} else if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		perror("recv");
		return -1;
	} else if ((size_t)ret >= sizeof(buffer)) {
		printf("Netlink buffer overflow (%zi)\n", ret);
		return -1;
	}

	printf("Read %zi bytes from netlink\n", ret);
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

	if (nlh->nlmsg_flags & MSG_TRUNC)
		return -1;

	for (int len = ret; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rth;
		int if_index;
	     
		switch (nlh->nlmsg_type) {

		case RTM_NEWLINK:
			_fallthrough_;
		case RTM_DELLINK:
			struct ifinfomsg *ifi = NLMSG_DATA(nlh);
			char if_name[128];
			rth = IFLA_RTA(ifi);
			if_index = ifi->ifi_index;

			for (int rtl = IFLA_PAYLOAD(nlh); RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
				if (rth->rta_type == IFLA_IFNAME)
					strcpy(if_name, RTA_DATA(rth));
			}

			if (nlh->nlmsg_type == RTM_NEWLINK) {
				printf("Added interface %s, index %i\n", if_name, if_index);
				netdev_add(if_index, if_name);
			} else {
				printf("Deleted interface %s, index %i\n", if_name, if_index);
				netdev_del(if_index);
			}
			break;

		case RTM_NEWADDR:
			_fallthrough_;
		case RTM_DELADDR:
			struct ifaddrmsg *ifa = NLMSG_DATA(nlh);
			char if_addr[1024];
			rth = IFA_RTA(ifa);
			if_index = ifa->ifa_index;

			for (int rtl = IFA_PAYLOAD(nlh); RTA_OK(rth, rtl); rth = RTA_NEXT(rth, rtl)) {
				if (rth->rta_type != IFA_LOCAL)
					continue;

				if (!inet_ntop(ifa->ifa_family, RTA_DATA(rth), if_addr, sizeof(if_addr)))
					continue;

				if (nlh->nlmsg_type == RTM_NEWADDR)
					netdev_add_addr(if_index, if_addr);
				else
					netdev_del_addr(if_index, if_addr);
			}
			break;

		case NLMSG_DONE:
			break;

		default:
			printf("Unhandled netlink type: %i\n", nlh->nlmsg_type);
			break;
		}
	}

	return 1;
}

static int
read_netlink(int nfd)
{
	int ret;

	while (true) {
		ret = read_netlink_once(nfd);
		if (ret <= 0)
			break;
	}

	return ret;
}

static int
setup_signalfd()
{
	int ret;
	sigset_t sigset;

	ret = sigfillset(&sigset);
	if (ret < 0)
		perror("sigfillset");

	ret = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (ret < 0)
		perror("sigprocmask");

	int fd = signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd < 0)
		perror("signalfd");

	return fd;
}

static int
read_signalfd(int sfd)
{
	struct signalfd_siginfo sig;

	int ret = read(sfd, &sig, sizeof(sig));
	if (ret < 0)
		perror("read");

	// man signal(7)
	printf("Got signal: %u %s\n", (unsigned)sig.ssi_signo, strsignal(sig.ssi_signo));
	if (sig.ssi_signo == SIGTERM) {
		printf("Signal was SIGTERM\n");
		quit = 1;
	}

	if (sig.ssi_signo == SIGINT) {
		printf("Signal was SIGINT\n");
		quit = 1;
	}

	return 0;
}

static pid_t
sys_clone3(struct clone_args *args)
{
	return (pid_t)syscall(SYS_clone3, args, sizeof(struct clone_args));
}

#define ptr_to_u64(ptr) ((__u64)((uintptr_t)(ptr)))

static int
exec_helper() {
	pid_t pid;
	int pidfd;

	struct clone_args args = {
		/* CLONE_PIDFD */
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_CLEAR_SIGHAND,
		.exit_signal = 0,
	};
	pid = sys_clone3(&args);

	if (pid < 0) {
		perror("clone3");
		return -1;
	} else if (pid == 0) {
		/* Child */
		printf("In child process. Sleeping..\n");
		sleep(5);
		printf("Exiting child process.\n");
		exit(0);
	} else {
		/* Parent */
		printf("Created child PID %d with pidfd %d\n", pid, pidfd);
		return pidfd;
	}
}

static int
epoll_monitor(int efd, int fd)
{
	int ret;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET,
		.data.fd = fd,
	};
	ret = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (ret < 0)
		perror("epoll_ctl");
	return ret;
}

static int
event_loop()
{
	_cleanup_close_ int efd = -1;
	_cleanup_close_ int sfd = setup_signalfd();
	_cleanup_close_ int nfd = setup_netlinkfd();
	_cleanup_close_ int tfd = setup_timerfd();
	_cleanup_close_ int cfd = -1;

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0) {
		perror("epoll_create");
		exit(1);
	}

	epoll_monitor(efd, sfd);
	epoll_monitor(efd, nfd);
	epoll_monitor(efd, tfd);

	printf("sfd %i nfd %i tfd %i\n", sfd, nfd, tfd);

	while (!quit) {
		struct epoll_event ev;
		int ret = epoll_wait(efd, &ev, 1, -1);
		if (ret <= 0) {
			perror("epoll");
			continue;
		} else if (ret == 0) {
			continue;
		}

		printf("FD is %i\n", ev.data.fd);

		if (ev.data.fd == nfd) {
			read_netlink(nfd);
			arm_timerfd(tfd);

		} else if (ev.data.fd == tfd) {
			printf("Timer data is available now\n");
			read_timerfd(tfd);
			cfd = exec_helper();
			printf("Child pidfd = %i\n", cfd);
			struct netdev *dev;
			list_for_each_entry(dev, &netdevs, list) {
				printf("Got a netdev, index %i, name %s\n", dev->index, dev->name);
			}

		} else if (ev.data.fd == sfd) {
			printf("Signal data is available now\n");
			read_signalfd(sfd);
		}
	}

	netdev_del_all();
	return 0;
}

int
main(_unused_ int argc, _unused_ char **argv)
{
	unsigned count = 0;

	while (true) {
		quit = 0;
		event_loop();
		printf("LOOP EXIT\n");
		count++;
		if (count > 3)
			break;
	}
}

