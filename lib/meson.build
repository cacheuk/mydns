# lib/meson.build

# This project was 'noinst_LIBRARIES = libmydnsutil.a'
# noinst_HEADERS were mydnsutil.h gettext.h getopt.h
# AM_CPPFLAGS was @INTLINCLUDE@ @SQLINCLUDE@
# libmydnsutil_a_SOURCES were alloca.c cidr.c conf.c error.c getopt.c getopt1.c getoptstr.c inet_pton.c inet_ntop.c ip.c passinput.c string.c strsep.c strsep_quotes.c wildcard.c
# libmydnsutil_a_LIBADD was @ALLOCA@

project('mydnsutil', 'c') # Subproject name for clarity
cc = meson.get_compiler('c')

# Get dependencies from the main project if they were declared with subproject_variable_name
# For now, assume they are available via project_args or already handled in root meson.build for include paths
# sql_dep = dependency('mysqlclient', required : false) # or pgsql, this needs to be dynamic based on parent option
# intl_dep = dependency('libintl', required : false)

# Check for alloca explicitly as it was in LIBADD
alloca_lib = []
if cc.has_function('alloca')
  # typically no library needed if function exists
elif cc.has_function('_alloca')
  # typically no library needed
elif cc.has_header('alloca.h')
  # alloca.h might provide it
else
  # If alloca.c is part of sources, it might provide it.
  # Autoconf's @ALLOCA@ could be -lalloca or empty or point to an object file.
  # Meson handles this differently; if alloca.c is in sources, it's compiled in.
  # If a separate liballoca is needed, it would be a dependency.
  # For now, assume alloca.c from sources if not found as a function.
  message('alloca function not found by compiler, relying on alloca.c if present in sources.')
endif


libmydnsutil_sources = [
  'alloca.c', # This was in sources, may conflict if system alloca is used.
              # Autoconf might have conditionally compiled this.
              # For now, include it and let the build system handle potential duplicate symbols if any.
  'cidr.c',
  'conf.c',
  'error.c',
  'getopt.c',
  'getopt1.c',
  'getoptstr.c',
  'inet_pton.c',
  'inet_ntop.c',
  'ip.c',
  'passinput.c',
  'string.c',
  'strsep.c',
  'strsep_quotes.c',
  'wildcard.c'
]

# Headers that are used by this library or exported by it
# For a static 'noinst_LIBRARIES', headers are typically not 'installed' globally
# but are used by other parts of the same project.
# We declare them for completeness and for use by other targets in this project.
libmydnsutil_headers = [
  'mydnsutil.h',
  'gettext.h', # This is a local gettext.h, not the system one.
  'getopt.h'   # This is a local getopt.h
]

# AM_CPPFLAGS from Makefile.am was @INTLINCLUDE@ @SQLINCLUDE@
# These are expected to be set globally by the root meson.build file (add_project_arguments)
# or passed as part of dependency objects.

libmydnsutil = static_library('mydnsutil',
  libmydnsutil_sources,
  include_directories: include_directories('.'), # so internal headers can be found with "header.h"
  dependencies : alloca_lib, # if alloca needs a separate lib
  c_args: [] # Add any specific c_args if needed, e.g. from AM_CPPFLAGS if not global
)

# This is how other meson files can get this library
# This variable name 'libmydnsutil_dep' should be used in the root meson.build to get this library
# For now, we just define it. The root meson.build needs to be updated to consume this if it uses subproject()
# However, if just using subdir(), the library object itself (libmydnsutil) is directly available.
libmydnsutil_dep = declare_dependency(
  link_with : libmydnsutil,
  include_directories : include_directories('.') # Makes mydnsutil.h available to other components
)

# For use in root meson.build if using subdir() approach and need to get the variable
meson.override_dependency('libmydnsutil', libmydnsutil_dep)
