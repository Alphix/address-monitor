/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <systemd/sd-daemon.h>

#include "utils.h"
#include "ansi-colors.h"
#include "main.h"

unsigned debug_mask = DBG_ERROR | DBG_INFO;

static const char *ansi_red = "";
static const char *ansi_green = "";
static const char *ansi_yellow = "";
static const char *ansi_blue = "";
static const char *ansi_magenta = "";
static const char *ansi_grey = "";
static const char *ansi_normal = "";

static void
enable_colors(void)
{
        ansi_red = ANSI_RED;
        ansi_green = ANSI_GREEN;
        ansi_yellow = ANSI_YELLOW;
        ansi_blue = ANSI_BLUE;
        ansi_magenta = ANSI_MAGENTA;
        ansi_grey = ANSI_GREY;
        ansi_normal = ANSI_NORMAL;
}

static void
set_logging_type(bool *use_colors, bool *sd_daemon)
{
	int fd;
	const char *e;

	/* assume we're not launched by systemd when daemonized */
	if (config.daemonize) {
		*sd_daemon = false;
		*use_colors = false;
		return;
	}

	if (config.log_file) {
		*sd_daemon = false;
		*use_colors = false;
		return;
	}

	if (getenv("NO_COLOR")) {
		*sd_daemon = false;
		*use_colors = false;
		return;
	}

	fd = fileno(stderr);
	if (fd < 0) {
		/* Umm... */
		*sd_daemon = true;
		*use_colors = false;
		return;
	}

	if (!isatty(fd)) {
		*sd_daemon = true;
		*use_colors = false;
		return;
	}

	/* systemd wouldn't normally set TERM */
	e = getenv("TERM");
	if (!e) {
		*sd_daemon = true;
		*use_colors = false;
		return;
	}

	if (streq(e, "dumb")) {
		*sd_daemon = false;
		*use_colors = false;
		return;
	}

	*sd_daemon = false;
	*use_colors = true;
}

static void msg(enum debug_lvl lvl, const char *fmt, va_list ap)
	__attribute__ ((format (printf, 2, 0)));

static void
msg(enum debug_lvl lvl, const char *fmt, va_list ap)
{
	static bool first = true;
	static bool sd_daemon;
	const char *color;
	const char *sd_lvl;

	assert_return(lvl != 0 && !empty_str(fmt) && ap);

	if (first) {
		bool use_colors;

		set_logging_type(&use_colors, &sd_daemon);
		if (use_colors)
			enable_colors();

		first = false;
	}

	switch (lvl) {
	case DBG_ERROR:
		sd_lvl = SD_ERR;
		color = ansi_red;
		break;
	case DBG_VERBOSE:
		sd_lvl = SD_INFO;
		color = NULL;
		break;
	case DBG_INFO:
		sd_lvl = SD_NOTICE;
		color = NULL;
		break;
	case DBG_DEBUG:
		_fallthrough_;
	default:
		sd_lvl = SD_DEBUG;
		color = ansi_grey;
		break;
	}

	if (sd_daemon)
		fprintf(stderr, "%s", sd_lvl);
	else if (color)
		fprintf(stderr, "%s", color);

	vfprintf(config.log_file ? config.log_file : stderr, fmt, ap);
	if (config.log_file)
		fflush(config.log_file);

	if (color)
		fprintf(stderr, "%s", ansi_normal);
}

void
__debug(enum debug_lvl lvl, const char *fmt, ...)
{
	va_list ap;

	assert_return(lvl != 0 && !empty_str(fmt));

	va_start(ap, fmt);
	msg(lvl, fmt, ap);
	va_end(ap);
}

_noreturn_ void
__die(const char *fmt, ...)
{
	va_list ap;

	if (!empty_str(fmt)) {
		va_start(ap, fmt);
		msg(DBG_ERROR, fmt, ap);
		va_end(ap);
	} else
		error("fmt not set");

	sd_notifyf(0,
		   "STOPPING=1\n"
		   "STATUS=Error, shutting down");
	exit(EXIT_FAILURE);
}
