# src/lib/meson.build

# This project was 'noinst_LIBRARIES = libmydns.a'
# AM_CPPFLAGS was @INTLINCLUDE@ @UTILINCLUDE@ @SQLINCLUDE@
# noinst_HEADERS were bits.h header.h mydns.h
# libmydns_a_SOURCES were ip.c question.c rr.c soa.c sql.c str.c unencode.c key.c

cc = meson.get_compiler('c')

# @UTILINCLUDE@ means it needs headers from ../../lib
# This needs to point to the 'lib' directory in the root of the project.
lib_include_path = include_directories('../../lib')


libmydns_sources = [
  'ip.c',
  'question.c',
  'rr.c',
  'soa.c',
  'sql.c',
  'str.c',
  'unencode.c',
  'key.c'
]

libmydns_headers = [
  'bits.h',
  'header.h',
  'mydns.h'
]

# AM_CPPFLAGS: @INTLINCLUDE@ @UTILINCLUDE@ @SQLINCLUDE@
# These are assumed to be added globally in the root meson.build or via dependencies.
# We specifically add lib_include_path for @UTILINCLUDE@.
# SQLINCLUDE and INTLINCLUDE are handled by dependencies or global flags.

libmydns = static_library('mydns',
  libmydns_sources,
  include_directories: [include_directories('.'), lib_include_path], # current dir for its own headers, and ../../lib for mydnsutil.h
  c_args: [] # Add any specific c_args if needed
)

# This is how other meson files can get this library.
# The root meson.build needs to be updated to use this.
lib_mydns_dep = declare_dependency(
  link_with : libmydns,
  include_directories : [include_directories('.'), lib_include_path] # Makes its headers available
)

# For use in root meson.build if using subdir() approach
meson.override_dependency('libmydns', lib_mydns_dep)
