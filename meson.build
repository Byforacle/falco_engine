#
# Copyright (c) 2022-2023 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('DOCA_SAMPLE', 'C', 'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('/opt/mellanox/doca/applications/VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug'],
	meson_version: '>= 0.61.2'
)

SAMPLE_NAME = 'regex_scan'

# Comment this line to restore warnings of experimental DOCA features
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: ['c', 'cpp'])

sample_dependencies = []
# Required for all DOCA programs
sample_dependencies += dependency('doca')
# 3rd Party dependencies
# None

sample_srcs = [
	# The sample itself
	SAMPLE_NAME + '_sample.c',
	# Main function for the sample's executable
	SAMPLE_NAME + '_main.c',
	# Common code for all DOCA samples
	'../../common.c',
	# Common code for all DOCA applications
	'../../../applications/common/src/utils.c',
]

sample_inc_dirs  = []
# Common DOCA logic (samples)
sample_inc_dirs += include_directories('../..')
# Common DOCA logic
sample_inc_dirs += include_directories('../../..')
# Common DOCA logic (applications)
sample_inc_dirs += include_directories('../../../applications/common/src')

# 原始的全文扫描程序
executable('doca_' + SAMPLE_NAME, sample_srcs,
	c_args : '-Wno-missing-braces',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)

# 新的按行扫描JSON数据程序
sample_line_srcs = [
	# The sample itself
	SAMPLE_NAME + '_sample.c',
	# Main function for line-by-line scanning
	SAMPLE_NAME + '_line_main.c',
	# Common code for all DOCA samples
	'../../common.c',
	# Common code for all DOCA applications
	'../../../applications/common/src/utils.c',
]

executable('doca_' + SAMPLE_NAME + '_lines', sample_line_srcs,
	c_args : '-Wno-missing-braces',
	dependencies : sample_dependencies,
	include_directories: sample_inc_dirs,
	install: false)
