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

#include "list.h"

int quit = 0;

LIST_HEAD(netdevs);

struct netdev {
	int index;
	char *name;
	bool monitored;
	struct list_head list;
};

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
	if (ret != msglen) {
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

static int
read_netlink(int fd)
{
	char buffer[16 * 1024];

	printf("Reading netlink\n");
	ssize_t ret = recv(fd, buffer, sizeof(buffer), 0);
	printf("Read netlink: %i\n", (int)ret);

	if (ret == 0) {
		return 0;
	} else if (ret < 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			perror("recv");
			return 0;
		}
		return -1;
	} else if (ret > sizeof(buffer)) {
		return 0;
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

	if (nlh->nlmsg_flags & MSG_TRUNC)
		return 0;

	int len = ret;

	while ((NLMSG_OK(nlh, len)) && (nlh->nlmsg_type != NLMSG_DONE)) {
		if ((nlh->nlmsg_type == RTM_NEWLINK) ||
		    (nlh->nlmsg_type == RTM_DELLINK)) {

			int attlen;
			struct rtattr *retrta;
			struct ifinfomsg *retinfo;
			retinfo = NLMSG_DATA(nlh);
			if (nlh->nlmsg_type == RTM_NEWLINK) {
				printf("Added interface, index %i\n", retinfo->ifi_index);
			} else {
				printf("Deleted interface, index %i\n", retinfo->ifi_index);
			}
			retrta = IFLA_RTA(retinfo);
			attlen = IFLA_PAYLOAD(nlh);
			char prname[128] = {0, };
			while (RTA_OK(retrta, attlen)) {
				if (retrta->rta_type == IFLA_IFNAME) {
					strcpy(prname, RTA_DATA(retrta));
					printf("    Name: %s\n", prname);
				}
				retrta = RTA_NEXT(retrta, attlen);
			}

			struct netdev *dev = malloc(sizeof(*dev));
			dev->index = retinfo->ifi_index;
			dev->name = strdup(prname);
			dev->monitored = true;
			list_add(&dev->list, &netdevs);
		}

		if ((nlh->nlmsg_type == RTM_NEWADDR) ||
		    (nlh->nlmsg_type == RTM_DELADDR)) {

			struct ifaddrmsg *ifa = (struct ifaddrmsg *)NLMSG_DATA(nlh);
			struct rtattr *rth = IFA_RTA(ifa);
			int rtl = IFA_PAYLOAD(nlh);

			while (rtl && RTA_OK(rth, rtl)) {
				if (rth->rta_type == IFA_LOCAL) {
					char tmp[1024];
					if (inet_ntop(ifa->ifa_family, RTA_DATA(rth), tmp, sizeof(tmp)))
						printf("%i: %s %s\n", ifa->ifa_index, (nlh->nlmsg_type == RTM_NEWADDR) ? "ADD" : "DEL", tmp);
				}
				rth = RTA_NEXT(rth, rtl);
			}
		}
		nlh = NLMSG_NEXT(nlh, len);
	}
	return 0;
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

int
main(int argc, char **argv)
{
	int efd;
	int sfd = setup_signalfd();
	int nfd = setup_netlinkfd();
	int tfd = setup_timerfd();
	int cfd;

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
			printf("Netlink data is available now\n");
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

	return 0;
}
