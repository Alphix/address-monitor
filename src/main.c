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

#include "config.h"
#include "utils.h"

static enum states {
	RUNNING,
	RELOADING,
	STOPPING,
} state = RUNNING;

static bool pending_changes = false;

static LIST_HEAD(netdevs);

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

	pending_changes = true;
	return 0;
}

static unsigned
netdev_del(int index)
{
	struct netdev *dev, *tmp;
	unsigned r = 0;

	list_for_each_entry_safe(dev, tmp, &netdevs, list) {
		if (dev->index != index)
			continue;
		list_del(&dev->list);
		free(dev->name);
		free(dev);
		r++;
	}

	pending_changes = true;
	return r;
}

static unsigned
netdev_del_all()
{
	struct netdev *dev, *tmp;
	unsigned r = 0;

	list_for_each_entry_safe(dev, tmp, &netdevs, list) {
		list_del(&dev->list);
		free(dev->name);
		free(dev);
		r++;
	}

	pending_changes = true;
	return r;
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
	pending_changes = true;
	return -1;
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
	pending_changes = true;
	return -1;
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
	char buffer[16 * 1024];
	ssize_t r;
       
	r = recv(nfd, buffer, sizeof(buffer), 0);
	if (r == 0) {
		return 0;
	} else if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		perror("recv");
		return -1;
	} else if ((size_t)r >= sizeof(buffer)) {
		printf("Netlink buffer overflow (%zi)\n", r);
		return -1;
	}

	printf("Read %zi bytes from netlink\n", r);
	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;

	if (nlh->nlmsg_flags & MSG_TRUNC)
		return -1;

	for (int len = r; NLMSG_OK(nlh, len); nlh = NLMSG_NEXT(nlh, len)) {
		struct rtattr *rth;
		int if_index;
	     
		printf("Netlink msg type: %i\n", nlh->nlmsg_type);
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
netlink_read(int nfd)
{
	int r;

	while (true) {
		r = netlink_read_once(nfd);
		if (r <= 0)
			break;
	}

	return r;
}

static int
netlink_get_names(int sock)
{
	struct {
	    struct nlmsghdr nlhdr;
	    struct ifinfomsg infomsg;
	} msg;
	size_t msglen = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	ssize_t r;

	// NLM_F_REQUEST - ask the kernel for data
	// NLM_F_ROOT    - provide all the addresses
	// RTM_GETLINK   - link information
	// AF_UNSPEC     - any kind of link
	memset(&msg, 0, sizeof(msg));
	msg.nlhdr.nlmsg_len    = msglen;
	msg.nlhdr.nlmsg_flags  = NLM_F_REQUEST | NLM_F_ROOT;
	msg.nlhdr.nlmsg_type   = RTM_GETLINK;
	msg.infomsg.ifi_family = AF_UNSPEC;

	r = send(sock, &msg, msglen, 0);
	if (r < 0 || (size_t)r != msglen) {
		fprintf(stderr, "Error sending netlink msg\n");
	}

	return r;
}

static int
netlink_init()
{
	int fd;
	struct sockaddr_nl snl = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR,
	};

	fd = socket(PF_NETLINK, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (fd < 0) {
		perror("netlink socket");
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&snl, sizeof(snl)) < 0) {
		perror("bind");
		/* FIXME: add xclose */
		close(fd);
		return -1;
	}

	if (netlink_get_names(fd) < 0) {
		/* FIXME: add xclose */
		close(fd);
		return -1;
	}

	return fd;
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
	if (r == 0) {
		return 0;
	} else if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		perror("read timerfd");
		return -1;
	} else if ((size_t)r != sizeof(exp)) {
		printf("timerfd weird read size: %zi\n", r);
		return -1;
	}

	printf("Timer expiry: %" PRIu64 "\n", exp);
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

	return r;
}

static int
timerfd_arm(int tfd)
{
	struct itimerspec new_value;
	struct itimerspec old_value;

	new_value.it_value.tv_sec = 10;
	new_value.it_value.tv_nsec = 0;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = 0;

	return timerfd_settime(tfd, 0, &new_value, &old_value);
}

static int
timerfd_init()
{
	int fd;

	fd = timerfd_create(CLOCK_BOOTTIME, TFD_NONBLOCK | TFD_CLOEXEC);
	if (fd < 0) {
		perror("timerfd_create");
		return -1;
	}

	return fd;
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
	if (r == 0) {
		return 0;
	} else if (r < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return 0;
		else if (errno == EINTR)
			return 1;
		perror("read signalfd");
		return -1;
	} else if ((size_t)r != sizeof(sig)) {
		printf("signalfd weird read size: %zi\n", r);
		return -1;
	}

	printf("Received signal (%u): %s\n", (unsigned)sig.ssi_signo, strsignal(sig.ssi_signo));
	switch (sig.ssi_signo) {
	case SIGINT:
		_fallthrough_;
	case SIGTERM:
		state = STOPPING;
		break;
	case SIGHUP:
		state = RELOADING;
		break;
	case SIGUSR1:
		struct netdev *dev;
		printf("Dumping list of known netdevs:\n");
		list_for_each_entry(dev, &netdevs, list) {
			printf("\tnetdev: index %i, name %s\n", dev->index, dev->name);
		}
		break;
	default:
		break;
	}

	return 1;
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
	int r;
	sigset_t sigset;

	r = sigfillset(&sigset);
	if (r < 0)
		perror("sigfillset");

	r = sigprocmask(SIG_BLOCK, &sigset, NULL);
	if (r < 0)
		perror("sigprocmask");

	int fd = signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
	if (fd < 0)
		perror("signalfd");

	return fd;
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

		perror("waitid");
		close(*cfd);
		*cfd = -1;
		return -1;
	}

	if (info.si_pid == 0)
		return 0;

	switch (info.si_code) {
	case CLD_EXITED:
		printf("Child exited, status: %i\n", info.si_status);
		break;
	case CLD_KILLED:
		printf("Child killed, signal: %i\n", info.si_status);
		break;
	case CLD_DUMPED:
		printf("Child dumped, signal: %i\n", info.si_status);
		break;
	case CLD_STOPPED:
		printf("Child stopped, signal: %i\n", info.si_status);
		break;
	case CLD_CONTINUED:
		printf("Child continued, signal: %i\n", info.si_status);
		break;
	case CLD_TRAPPED:
		printf("Traced child has trapped, signal: %i\n", info.si_status);
		break;
	default:
		printf("Unknown child state: %i\n", info.si_code);
		break;
	}

	close(*cfd);
	*cfd = -1;
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

static int
sys_pidfd_send_signal(int pidfd, int signal)
{
	return syscall(SYS_pidfd_send_signal, pidfd, signal, NULL, 0);
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
		.pidfd = ptr_to_u64(&pidfd),
		.flags = CLONE_PIDFD | CLONE_CLEAR_SIGHAND,
		/* setting exit_signal to zero breaks waitid */
		.exit_signal = SIGCHLD,
	};
	pid = sys_clone3(&args);

	if (pid < 0) {
		perror("clone3");
		return -1;
	} else if (pid == 0) {
		/* Child */
		printf("In child process. Sleeping..\n");
		sleep(10);
		printf("Exiting child process.\n");
		exit(0);
	} else {
		/* Parent */
		printf("Created child PID %d with pidfd %d\n", pid, pidfd);
		pending_changes = false;
		return pidfd;
	}
}

static int
epoll_monitor(int efd, int fd)
{
	int r;
	struct epoll_event ev = {
		.events = EPOLLIN | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET,
		.data.fd = fd,
	};

	r = epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev);
	if (r < 0)
		perror("epoll_ctl");
	return r;
}

static int
event_loop()
{
	_cleanup_close_ int efd = -1;
	_cleanup_close_ int sfd = signalfd_init();
	_cleanup_close_ int nfd = netlink_init();
	_cleanup_close_ int tfd = timerfd_init();
	int cfd = -1;

	efd = epoll_create1(EPOLL_CLOEXEC);
	if (efd < 0) {
		perror("epoll_create");
		exit(1);
	}

	epoll_monitor(efd, sfd);
	epoll_monitor(efd, nfd);
	epoll_monitor(efd, tfd);

	printf("sfd %i nfd %i tfd %i\n", sfd, nfd, tfd);

	while (state == RUNNING) {
		struct epoll_event ev;
		int r;

		if (pending_changes)
			timerfd_arm(tfd);

	       	r = epoll_wait(efd, &ev, 1, -1);
		if (r <= 0) {
			perror("epoll");
			continue;
		} else if (r == 0) {
			continue;
		}

		printf("Received event on fd %i\n", ev.data.fd);

		/* FIXME: check other epoll events and that ev.data.fd >= 0 */
		if (ev.data.fd == nfd) {
			netlink_read(nfd);

		} else if (ev.data.fd == tfd) {
			timerfd_read(tfd);
			cfd = exec_helper();
			printf("Child pidfd = %i\n", cfd);
			epoll_monitor(efd, cfd);

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
		printf("Invalid option(s)\n");

	printf("Usage: %s [OPTION...] [IFNAME...]\n"
	       "\n"
	       "Valid options:\n"
	       "  -c, --cfg=FILE\tread configuration from FILE\n"
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
			{ "cfg",	required_argument,	0, 'c' },
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
			printf("Config dir: %s\n", optarg);
			break;
		case 'l':
			printf("Logfile: %s\n", optarg);
			break;
		case 'v':
			printf("Verbose output\n");
			break;
		case 'd':
			printf("Debug output\n");
			break;
		case 'h':
			printf("Help output\n");
			usage(false);
			break;
		default:
			printf("Unknown option\n");
			usage(true);
			break;
		}
	}

	if (optind < argc) {
		while (optind < argc) {
			printf("Extra argument: %s\n", argv[optind]);
			optind++;
		}
	}
}

int
main(int argc, char **argv)
{
	unsigned count = 0;

	// FIXME: assert_die(argc > 0 && argv, "invalid arguments");

	config_init(argc, argv);

	while (true) {
		if (state == STOPPING)
			break;
		state = RUNNING;
		pending_changes = true;
		event_loop();
		printf("LOOP EXIT\n");
		count++;
		if (count > 3)
			break;
	}
}

