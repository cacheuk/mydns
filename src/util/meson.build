# src/util/meson.build

project('mydns_utils', 'c')
cc = meson.get_compiler('c')

# Dependencies (similar to src/mydns/meson.build)
libmydns_dep = dependency('libmydns', internal: true)
libmydnsutil_dep = dependency('libmydnsutil', internal: true)
gettext_dep = dependency('libintl', required: false)
socket_dep = cc.find_library('socket', required : false)
nsl_dep = cc.find_library('nsl', required : false)
math_dep = cc.find_library('m', required : false)

db_dep = disabler()
# Access options from the main project using get_option()
if get_option('enable-mysql')
  db_dep = dependency('mysqlclient', required : true)
elif get_option('enable-pgsql')
  db_dep = dependency('libpq', required : true)
else
  # Default to mysql if nothing explicit, as per root meson.build logic (simplified here)
  db_dep = dependency('mysqlclient', required : false)
  if not db_dep.found()
    # Attempt to find pgsql only if mysql was the default and not found.
    db_dep = dependency('libpq', required : false)
    if not db_dep.found()
        message('mydns_utils: No database dependency found or configured in root.')
    endif
  endif
endif

openssl_dep = disabler()
if get_option('with-openssl')
  openssl_dep = dependency('openssl', required : true)
endif

common_deps = [libmydns_dep, libmydnsutil_dep]
if gettext_dep.found()
  common_deps += gettext_dep
endif
if db_dep.found()
  common_deps += db_dep
endif
if openssl_dep.found()
  common_deps += openssl_dep
endif
if socket_dep.found()
  common_deps += socket_dep
endif
if nsl_dep.found()
  common_deps += nsl_dep
endif
if math_dep.found()
  common_deps += math_dep
endif

# AM_CPPFLAGS was @UTILINCLUDE@ @MYDNSINCLUDE@ @INTLINCLUDE@ @SQLINCLUDE@ @SSLINCLUDE@
# DEFS was -DLOCALEDIR="$(localedir)" -DSBINDIR="$(sbindir)"
localedir = join_paths(get_option('prefix'), get_option('datadir'), 'locale')
# SBINDIR should be the path string, not the directory object from get_option('sbindir')
# The original define likely expected a string path.
# get_option('sbindir') returns the path relative to prefix, or absolute if set so.
# For consistency with how prefix/sbindir is handled by Meson, let's ensure it's a full path.
# However, executables are installed *into* sbindir, the define might be for finding mydns exec.
# Let's assume it's the directory where sbin programs are installed.
sbindir_str = join_paths(get_option('prefix'), get_option('sbindir'))


common_c_args = [
  '-DLOCALEDIR="@0@"'.format(localedir),
  '-DSBINDIR="@0@"'.format(sbindir_str) # Use the path string
]

# Include directories
# @UTILINCLUDE@ -> ../../lib
# @MYDNSINCLUDE@ -> ../lib (src/lib)
current_inc = include_directories('.') # For local headers like util.h, libptr.h
lib_util_inc = include_directories('../../lib') # for mydnsutil.h
lib_mydns_inc = include_directories('../lib')   # for mydns.h
common_include_dirs = [current_inc, lib_util_inc, lib_mydns_inc]

# Utility programs
# mydnscheck_SOURCES = check.c util.c
executable('mydnscheck',
  ['check.c', 'util.c'],
  dependencies : common_deps,
  include_directories : common_include_dirs,
  c_args : common_c_args,
  install : true,
  install_dir : get_option('bindir') # bin_PROGRAMS
)

# mydnsexport_SOURCES = export.c util.c
executable('mydnsexport',
  ['export.c', 'util.c'],
  dependencies : common_deps,
  include_directories : common_include_dirs,
  c_args : common_c_args,
  install : true,
  install_dir : get_option('bindir')
)

# mydnsimport_SOURCES = import.c import-axfr.c import-tinydns.c util.c
executable('mydnsimport',
  ['import.c', 'import-axfr.c', 'import-tinydns.c', 'util.c'],
  dependencies : common_deps,
  include_directories : common_include_dirs,
  c_args : common_c_args,
  install : true,
  install_dir : get_option('bindir')
)

# mydnsptrconvert_SOURCES = libptr.c libptr.h ptrconvert.c util.c
# libptr.h is a local header, included by libptr.c and ptrconvert.c
executable('mydnsptrconvert',
  ['libptr.c', 'ptrconvert.c', 'util.c'], # libptr.h will be found via common_include_dirs ('.')
  dependencies : common_deps,
  include_directories : common_include_dirs,
  c_args : common_c_args,
  install : true,
  install_dir : get_option('bindir')
)

# mydns_conf_SOURCES = conf.c
# This seems to be mydns-conf from the original Makefile.am
executable('mydns-conf',
  ['conf.c'], # Assuming this conf.c is specific to mydns-conf utility
  dependencies : common_deps, # Might not need all of these, but original used common LDADD for simplicity
  include_directories : common_include_dirs,
  c_args : common_c_args,
  install : true,
  install_dir : get_option('bindir')
)

# util.h is a local header (noinst_HEADERS in Automake terms)
# libptr.h is also local (noinst_HEADERS)
# These are made available by include_directories('.') via common_include_dirs.
# Removed _project_options_txt, using get_option() directly.
# Ensured SBINDIR definition uses a path string.
# Clarified local header handling.
