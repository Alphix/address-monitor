# SPDX-License-Identifier: GPL-2.0
project('address-monitor',
	'c',
	version: '3',
	license: 'GPL2',
	default_options : [
		'c_std=gnu18',
		'sysconfdir=/etc',
		'sharedstatedir=/var/lib',
		'warning_level=2',
		'b_lto=true',
	]
)

cc = meson.get_compiler('c')

cc_flags = [
	'-D_GNU_SOURCE',
]
cc_warning_flags = [
	'-Werror=implicit-function-declaration',	# A warning is too weak
	'-Werror=implicit-fallthrough', # No implicit fallthroughs in switch statements
]
cc_flags += cc.get_supported_arguments(cc_warning_flags)
cc_extra_flags = [
	'-ffunction-sections',	# Generate each function in a separate section
	'-fdata-sections',	# Ditto for data
]
cc_flags += cc.get_supported_arguments(cc_extra_flags)
add_project_arguments(cc_flags, language: 'c')

ld_flags = []
ld_extra_flags = [
	'-Wl,-z,defs',		# Detect and reject underlinking
	'-Wl,-z,now',		# Disable lazy binding
	'-Wl,-z,relro',		# Read-only segments after relocation
	'-Wl,--gc-sections',	# Remove unused sections
]
ld_flags += cc.get_supported_link_arguments(ld_extra_flags)
add_project_link_arguments(ld_flags, language: 'c')

sysconfdir = join_paths(get_option('sysconfdir'), meson.project_name())
localstatedir = join_paths(get_option('prefix'), get_option('sharedstatedir'), meson.project_name())

conf = configuration_data()
conf.set_quoted('VERSION', '@0@-@VCS_TAG@'.format(meson.project_version()))
conf.set_quoted('DEFAULT_CFG_DIR', sysconfdir)
conf.set_quoted('DEFAULT_DATA_DIR', localstatedir)

inc_config_h = include_directories('.')
dep_config_h = declare_dependency(
	sources: vcs_tag(
		command: ['git', 'rev-parse', '--short', 'HEAD'],
		fallback: get_option('profile') != 'default' ? 'devel' : 'stable',
		input: configure_file (
			output: 'config.h.in',
			input: 'config.h.in',
			configuration: conf
		),
		output: 'config.h'
	),
	include_directories : inc_config_h,
)

subdir('src')

