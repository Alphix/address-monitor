# SPDX-License-Identifier: GPL-2.0
srcs_address_monitor = [
	'main.c',
	'utils.c',
]

dep_libsystemd = dependency('libsystemd')

deps_address_monitor = [
	dep_libsystemd,
	dep_config_h,
]

executable(
	'address-monitor',
	srcs_address_monitor,
	install: true,
	install_dir: 'sbin',
	dependencies: deps_address_monitor,
)

