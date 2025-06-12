# src/mydns/meson.build

project('mydns_server', 'c')
cc = meson.get_compiler('c')

# Dependencies from the main project
# These should be discoverable if declared correctly in the root or passed via subproject options
# For subdir() approach, they are typically found using dependency('name', internal: true)
# if meson.override_dependency was used, or by getting variables from subproject objects.

libmydns_dep = dependency('libmydns', internal: true) # From src/lib
libmydnsutil_dep = dependency('libmydnsutil', internal: true) # From lib
gettext_dep = dependency('libintl', required : false) # GNU Gettext
db_dep = disabler() # Placeholder, this needs to be the actual db_dep from root. Use disabler() for optional deps.
openssl_dep = disabler() # Placeholder, this needs to be the actual openssl_dep from root

# Reconstruct dependencies based on what configure.ac and Makefile.am did.
# LDADD was @LIBMYDNS@ @LIBUTIL@ @LIBINTL@ @LIBSQL@ @LIBSSL@ @LIBSOCKET@ @LIBNSL@ @LIBM@
# LIBMYDNS is lib_mydns_dep
# LIBUTIL is libmydnsutil_dep
# LIBINTL is gettext_dep (if found)

# Socket and NSL libraries
socket_dep = cc.find_library('socket', required : false)
nsl_dep = cc.find_library('nsl', required : false)
math_dep = cc.find_library('m', required : false) # For -lm

# Database and SSL dependencies need to be resolved based on root project's choices
# This is a simplified way; a more robust way is to pass these as subproject options
# or use meson.get_cross_property or similar if set globally.
# For now, let's try to re-evaluate them based on options.
# This is not ideal as it duplicates logic but helps for a self-contained subdir.
# Note: _project_options_txt is not a standard Meson object.
# Options should be accessed via get_option('option_name') if this meson.build
# is part of the main project build (via subdir), or passed if it's a subproject.
# Assuming this is processed by `subdir()` in the root meson.build.

# Database
# This logic relies on options defined in the root meson_options.txt
if get_option('enable-mysql')
  db_dep = dependency('mysqlclient', required : true)
elif get_option('enable-pgsql')
  db_dep = dependency('libpq', required : true)
else
  # Default to mysql if nothing explicit, as per root meson.build logic (simplified here)
  db_dep = dependency('mysqlclient', required : false)
  if not db_dep.found()
    # Attempt to find pgsql only if mysql was the default and not found.
    # If user explicitly set an option that wasn't found, root meson.build would have errored.
    db_dep = dependency('libpq', required : false) # Try pgsql as a fallback if default mysql not found
    if not db_dep.found()
        # This path should ideally not be reached if root meson.build has already enforced a DB choice.
        message('mydns executable: No database dependency found or configured in root.')
    endif
  endif
endif

# SSL
if get_option('with-openssl')
  openssl_dep = dependency('openssl', required : true)
endif

all_deps = [libmydns_dep, libmydnsutil_dep]
if gettext_dep.found()
  all_deps += gettext_dep
endif
if db_dep.found() # Check .found() for dependencies that might be disabler() or optional
  all_deps += db_dep
endif
if openssl_dep.found()
  all_deps += openssl_dep
endif
if socket_dep.found()
  all_deps += socket_dep
endif
if nsl_dep.found()
  all_deps += nsl_dep
endif
if math_dep.found()
  all_deps += math_dep
endif

# AM_CPPFLAGS was @UTILINCLUDE@ @MYDNSINCLUDE@ @INTLINCLUDE@ @SQLINCLUDE@ @SSLINCLUDE@
# DEFS was -DLOCALEDIR="$(localedir)"
# $(localedir) is $(datadir)/locale
# In Meson, get_option('prefix') and get_option('datadir') are available.
localedir = join_paths(get_option('prefix'), get_option('datadir'), 'locale')
localedir_c_arg = '-DLOCALEDIR="@0@"'.format(localedir)


mydns_sources = [
  'alias.c', 'axfr.c', 'cache.c', 'conf.c', 'data.c', 'db.c', 'encode.c',
  'error.c', 'listen.c', 'main.c', 'queue.c', 'recursive.c',
  'reply.c', 'resolve.c', 'rr.c', 'sort.c', 'status.c', 'task.c',
  'tcp.c', 'udp.c', 'update.c', 'tsig.c'
]

mydns_headers = [
  'cache.h', 'named.h', 'task.h', 'update.h', 'tsig.h'
]

# Include directories for this target
# @UTILINCLUDE@ -> ../../lib
# @MYDNSINCLUDE@ -> ../lib (src/lib)
# @INTLINCLUDE@, @SQLINCLUDE@, @SSLINCLUDE@ are handled by dependencies or global args from root.
current_inc = include_directories('.') # for local headers like cache.h
lib_util_inc = include_directories('../../lib') # for mydnsutil.h etc from lib/
lib_mydns_inc = include_directories('../lib') # for mydns.h etc from src/lib/

executable('mydns',
  mydns_sources,
  dependencies : all_deps,
  include_directories : [current_inc, lib_util_inc, lib_mydns_inc],
  c_args : [localedir_c_arg], # Pass as a list
  install : true,
  install_dir : get_option('sbindir') # sbin_PROGRAMS
)

# Removed the _project_options_txt which is not a standard Meson feature.
# get_option() will correctly access options from the main project when this
# file is included via subdir().
# Initialized db_dep and openssl_dep to disabler() for safety if options are off.
# Ensured c_args is a list.
# Corrected include directory variables for clarity.
# Added .found() checks for optional dependencies before adding to all_deps.
# Refined the database dependency logic slightly for the case where neither is enabled
# and defaults are checked, though the root meson.build should enforce selection.
