project('mydns', 'c',
  version : '1.1.0',
  license : 'GPL-2.0-or-later',
  default_options : ['warning_level=2', 'c_std=gnu99']) # Added c_std for older C features

# Basic compiler and linker flags
add_project_arguments('-D_REENTRANT', language : 'c')

# Output location for compiled C header
# We will use meson's configuration data object to generate config.h
conf_data = configuration_data()
cc = meson.get_compiler('c')

# GNU gettext
conf_data.set('ENABLE_NLS', 0) # Default to NLS disabled
conf_data.set('HAVE_LIBINTL_H', 0) # Default

# Call subdir('intl') first. It may override 'libintl' if 'internal_gettext' is true
# (and system libintl is not found, as per logic in intl/meson.build).
subdir('intl') # This call must happen before `dependency('libintl')` is finalized.

# Now resolve the final 'libintl' dependency. It's either system, overridden internal, or not found.
# The `intl/meson.build` uses `get_option('internal_gettext')` and `dependency('libintl', required: false)`
# to decide if it should override.
final_gettext_dep = dependency('libintl', required : false)

if final_gettext_dep.found()
  message('Using gettext implementation (system or internal from intl/).')
  add_project_arguments('-DENABLE_NLS', language : 'c')
  conf_data.set('ENABLE_NLS', 1)
  # Check for libintl.h using the context of the found dependency
  if cc.has_header('libintl.h', dependencies: final_gettext_dep)
    conf_data.set('HAVE_LIBINTL_H', 1)
  else
    # This case implies the dependency is somehow incomplete or headers are not in expected paths.
    # If internal gettext is used, its include_directories should make libintl.h (or equivalent) findable.
    warning('libintl dependency found/overridden, but libintl.h not found in its include paths. Check intl/meson.build include_directories if using internal gettext.')
    # Still, if ENABLE_NLS is 1, code might expect HAVE_LIBINTL_H to be 1.
    # Forcing it to 1 if internal gettext is chosen and supposed to provide it.
    if get_option('internal_gettext') and not dependency('libintl', required:false).found() # checking if internal was intended
        message('Assuming internal gettext provides necessary headers for libintl.h functionality.')
        conf_data.set('HAVE_LIBINTL_H', 1) # Optimistic for internal lib
    endif
  endif
elif cc.has_function('gettext') and not get_option('internal_gettext') # Fallback to libc only if not attempting internal.
  message('Using gettext from libc (system libintl not found, internal_gettext=false).')
  add_project_arguments('-DENABLE_NLS', language : 'c')
  conf_data.set('ENABLE_NLS', 1)
  if cc.has_header('libintl.h') # Check system paths for libintl.h with libc gettext
      conf_data.set('HAVE_LIBINTL_H', 1)
  endif
else
  message('No gettext support found or enabled (system libintl not found, internal_gettext=false, and gettext not in libc or internal build failed). Internationalization will be disabled.')
endif


# Check for IPv6 support
if cc.has_header_symbol('netinet/in.h', 'in6_addr')
    add_project_arguments('-DHAVE_IPV6=1', language : 'c') # From AC_CHECK_IPV6
    conf_data.set('HAVE_IPV6', 1)
else
    add_project_arguments('-DHAVE_IPV6=0', language : 'c') # From AC_CHECK_IPV6
    conf_data.set('HAVE_IPV6', 0)
endif


# Check for sa_len in struct sockaddr_in (corresponds to AC_CHECK_SOCKADDR_SA_LEN)
if cc.has_member('struct sockaddr_in', 'sin_len', prefix : '#include <sys/socket.h>\n#include <netinet/in.h>')
  add_project_arguments('-DHAVE_SOCKADDR_SA_LEN=1', language : 'c')
  conf_data.set('HAVE_SOCKADDR_SA_LEN', 1)
else
  # This define was set to 0 if not found in original configure.ac via mydns.m4
  add_project_arguments('-DHAVE_SOCKADDR_SA_LEN=0', language : 'c')
  conf_data.set('HAVE_SOCKADDR_SA_LEN', 0)
endif


# Set some package-specific variables (from AC_MYDNS_PKGINFO)
conf_data.set_quoted('PACKAGE_NAME', 'mydns')
conf_data.set_quoted('PACKAGE_VERSION', '1.1.0')
conf_data.set_quoted('PACKAGE_STRING', 'mydns 1.1.0')
conf_data.set_quoted('PACKAGE_BUGREPORT', 'bboy@bboy.net')
conf_data.set_quoted('PACKAGE_URL', 'http://mydns.bboy.net')
conf_data.set_quoted('PACKAGE_COPYRIGHT', 'Copyright (C) 2002-2005 Don Moore') #Added from configure.ac
conf_data.set_quoted('PACKAGE_AUTHOR', 'Don Moore <bboy@bboy.net>') #Added from configure.ac
conf_data.set_quoted('MYDNS_CONF', get_option('sysconfdir') / 'mydns.conf') # From AC_MYDNS_CONF


# Database options
use_mysql_opt = get_option('enable-mysql')
use_pgsql_opt = get_option('enable-pgsql')
db_dep = disabler()
sql_include_dirs_str = '' # Store as string for add_project_arguments
db_name = ''

if use_mysql_opt and use_pgsql_opt
  error('Choose either MySQL or PostgreSQL, not both.')
elif use_mysql_opt
  db_dep = dependency('mysqlclient', required : true)
  sql_include_dirs_str = db_dep.get_variable(pkgconfig: 'includedir', internal:'mysql_includedir')
  db_name = 'MySQL'
  add_project_arguments('-DUSE_MYSQL=1', language : 'c') # From AC_CHECK_MYSQL
  conf_data.set('USE_MYSQL', 1)
  conf_data.set('USE_PGSQL', 0) # Ensure other DB is not set
elif use_pgsql_opt
  db_dep = dependency('libpq', required : true)
  sql_include_dirs_str = db_dep.get_variable(pkgconfig: 'includedir', internal:'pgsql_includedir')
  db_name = 'PostgreSQL'
  add_project_arguments('-DUSE_PGSQL=1', language : 'c') # From AC_CHECK_PGSQL
  conf_data.set('USE_PGSQL', 1)
  conf_data.set('USE_MYSQL', 0) # Ensure other DB is not set
else
  warning('Neither MySQL nor PostgreSQL was explicitly enabled. Trying to default to MySQL.')
  db_dep = dependency('mysqlclient', required : false)
  if db_dep.found()
    use_mysql_opt = true
    sql_include_dirs_str = db_dep.get_variable(pkgconfig: 'includedir', internal:'mysql_includedir')
    db_name = 'MySQL'
    add_project_arguments('-DUSE_MYSQL=1', language : 'c')
    conf_data.set('USE_MYSQL', 1)
    conf_data.set('USE_PGSQL', 0)
  else
    db_dep = dependency('libpq', required : false)
    if db_dep.found()
        use_pgsql_opt = true
        sql_include_dirs_str = db_dep.get_variable(pkgconfig: 'includedir', internal:'pgsql_includedir')
        db_name = 'PostgreSQL'
        add_project_arguments('-DUSE_PGSQL=1', language : 'c')
        conf_data.set('USE_PGSQL', 1)
        conf_data.set('USE_MYSQL', 0)
    else
        error('No database selected and neither MySQL nor PostgreSQL found. Please install one and/or set -Denable-mysql=true or -Denable-pgsql=true.')
    endif
  endif
endif

message('Configuring MyDNS ' + meson.project_version() + ' with ' + db_name + ' database support.')

# OpenSSL option (from AC_WITH_OPENSSL)
use_openssl_opt = get_option('with-openssl')
openssl_dep = disabler()
ssl_include_dirs_str = '' # Store as string
if use_openssl_opt
  openssl_dep = dependency('openssl', required : true)
  add_project_arguments('-DWITH_OPENSSL=1', language : 'c')
  conf_data.set('WITH_OPENSSL', 1)
  ssl_include_dirs_str = openssl_dep.get_variable(pkgconfig: 'includedir', internal: 'openssl_includedir')
else
  add_project_arguments('-DWITH_OPENSSL=0', language : 'c')
  conf_data.set('WITH_OPENSSL', 0)
endif

# Global include directories for SQL and SSL
# Must ensure these are actual paths before adding with -I
if sql_include_dirs_str != ''
  add_project_arguments('-I' + sql_include_dirs_str, language : 'c')
endif
if ssl_include_dirs_str != ''
  add_project_arguments('-I' + ssl_include_dirs_str, language : 'c')
endif

# Standard headers (from AC_CHECK_HEADERS)
std_headers = [
  'fcntl.h', 'getopt.h', 'libintl.h', 'netdb.h', 'pwd.h', 'signal.h', 'stdarg.h', 'termios.h', 'time.h',
  'sys/fcntl.h', 'sys/file.h', 'sys/ioctl.h', 'sys/resource.h',
  'sys/socket.h', 'sys/sockio.h', 'sys/time.h', 'sys/wait.h',
  'netinet/in.h', 'net/if.h', 'arpa/inet.h', 'inttypes.h'
]
foreach h : std_headers
  if cc.has_header(h)
    conf_data.set('HAVE_' + h.to_upper().underscorify().replace('.', '_'), 1)
  else
    conf_data.set('HAVE_' + h.to_upper().underscorify().replace('.', '_'), 0)
  endif
endforeach

# Typedefs, structures, and compiler characteristics.
conf_data.set('STDC_HEADERS', 1) # Meson ensures this (AC_HEADER_STDC)
if cc.compiles('const int i = 0;', name : 'C_CONST_CHECK')
    conf_data.set('CONST', 'const') # Autoconf's AC_C_CONST sets 'CONST' to 'const' or empty
else
    conf_data.set('CONST', '')
endif

types_to_check = ['uint8_t', 'uint16_t', 'uint32_t']
if cc.has_header('stdint.h')
    conf_data.set('HAVE_STDINT_H',1)
    foreach t : types_to_check
        if cc.has_type(t, prefix: '#include <stdint.h>')
            conf_data.set('HAVE_' + t.to_upper(), 1)
        else
            conf_data.set('HAVE_' + t.to_upper(), 0)
        endif
    endforeach
else
    conf_data.set('HAVE_STDINT_H',0)
    foreach t : types_to_check
        conf_data.set('HAVE_' + t.to_upper(), 0)
    endforeach
endif

# Library functions (from AC_CHECK_FUNCS)
funcs_to_check = ['memset', 'getpwuid', 'shutdown', 'inet_ntop', 'inet_pton', 'strsep']
foreach f : funcs_to_check
  if cc.has_function(f)
    conf_data.set('HAVE_' + f.to_upper(), 1)
  else
    conf_data.set('HAVE_' + f.to_upper(), 0)
  endif
endforeach

# AC_FUNC_ALLOCA
has_alloca_h_check = cc.has_header('alloca.h')
if has_alloca_h_check
  conf_data.set('HAVE_ALLOCA_H', 1)
else
  conf_data.set('HAVE_ALLOCA_H', 0)
endif

if cc.has_function('alloca')
  conf_data.set('HAVE_ALLOCA', 1)
elif cc.has_function('_alloca')
  conf_data.set('HAVE__ALLOCA', 1) # Windows specific
  conf_data.set('HAVE_ALLOCA', 0) # Ensure Autoconf's HAVE_ALLOCA is not set if only _alloca found
else
  # If neither alloca nor _alloca is found as a function,
  # Autoconf would then typically check if alloca.c (if provided) works or if alloca is in libc.
  # The original Makefile.am for libmydnsutil.a lists alloca.c in its sources.
  # If alloca.c is compiled into libmydnsutil, then code using alloca() would link.
  # For config.h, HAVE_ALLOCA should reflect if a usable alloca is expected.
  # If alloca.c is part of the sources and provides alloca(), then this should be 1.
  # Meson doesn't automatically infer this for config.h from source files.
  # For now, set HAVE_ALLOCA based on function check only, matching the previous logic more directly.
  # If alloca.c is meant to be a fallback, specific code usually checks #ifdef HAVE_ALLOCA.
  conf_data.set('HAVE_ALLOCA', 0)
endif

# Declarations (from AC_CHECK_DECLS) using cc.compiles
decls_to_check_map = {
  'strcasecmp': ['#include <strings.h>', 'int r = strcasecmp("a", "b");'],
  'strcoll': ['#include <string.h>', 'int r = strcoll("a", "b");'],
  'strerror': ['#include <string.h>', 'char *s = strerror(0);'],
  'strncasecmp': ['#include <strings.h>', 'int r = strncasecmp("a", "b", 1);'],
  'strsep': ['#include <string.h>', 'char actual_s[] = "test,string"; char *s_ptr = actual_s; char *p = strsep(&s_ptr, ",");']
}
foreach name, info : decls_to_check_map
  prefix = info[0]
  code = info[1]
  # Ensure main returns int, and variables used in a way that tests declaration
  test_code = prefix + '\nint main(void) { ' + code + ' return 0; }'
  if cc.compiles(test_code, name: 'check_decl_' + name)
    conf_data.set('HAVE_DECL_' + name.to_upper(), 1)
  else
    conf_data.set('HAVE_DECL_' + name.to_upper(), 0)
  endif
endforeach

# Other options from configure.ac
if get_option('enable-alias')
  conf_data.set('ENABLE_ALIAS', 1)
else
  conf_data.set('ENABLE_ALIAS', 0)
endif
if get_option('enable-static-build')
  conf_data.set('ENABLE_STATIC_BUILD', 1)
else
  conf_data.set('ENABLE_STATIC_BUILD', 0)
endif
if get_option('enable-profiling')
  conf_data.set('ENABLE_PROFILING', 1)
else
  conf_data.set('ENABLE_PROFILING', 0)
endif
if get_option('enable-debug')
  conf_data.set('ENABLE_DEBUG', 1)
else
  conf_data.set('ENABLE_DEBUG', 0)
endif
if get_option('enable-valgrind')
  conf_data.set('ENABLE_VALGRIND', 1)
else
  conf_data.set('ENABLE_VALGRIND', 0)
endif
if get_option('enable-strict')
  conf_data.set('ENABLE_STRICT', 1)
else
  conf_data.set('ENABLE_STRICT', 0)
endif
if get_option('enable-status')
  conf_data.set('ENABLE_STATUS', 1)
else
  conf_data.set('ENABLE_STATUS', 0)
endif
if get_option('disable-date-logging')
  conf_data.set('DISABLE_DATE_LOGGING', 1)
else
  conf_data.set('DISABLE_DATE_LOGGING', 0)
endif

# Apply compiler flags based on options
if get_option('enable-profiling')
  add_project_arguments('-pg', language : 'c')
  add_project_link_arguments('-pg', language : 'c')
endif

if get_option('enable-debug')
  add_project_arguments(['-g', '-DDEBUG'], language : 'c')
else
  add_project_arguments('-DNDEBUG', language : 'c') # NDEBUG is standard, unlike RELEASE
endif

if get_option('enable-valgrind')
  add_project_arguments(['-DVALGRIND', '-g'], language : 'c') # As per mydns.m4
endif

if get_option('enable-strict')
  strict_flags = ['-W', '-Wall', '-Wpointer-arith', '-Wcast-qual', '-Wcast-align', '-Wwrite-strings', '-Wstrict-prototypes', '-Wmissing-prototypes', '-Wmissing-declarations', '-Wredundant-decls', '-Wnested-externs', '-Winline']
  foreach flag : strict_flags
    if cc.has_argument(flag)
      add_project_arguments(flag, language: 'c')
    endif
  endforeach
endif

# Configure config.h
# meson.add_dist_script('config.h.in', 'config.h') # This was from step 1, replaced by configure_file
configure_file(input: 'config.h.in', output : 'config.h', configuration : conf_data)


# Subdirectories
# These need to be defined after all global project arguments and conf_data are set.
# Dependencies like db_dep, openssl_dep, gettext_dep need to be passed or available globally if used in subdirs.
global_project_deps = declare_dependency(
  dependencies: [db_dep, openssl_dep, final_gettext_dep],
  # include_directories: include_directories('.') # if config.h is needed by subprojects directly
)

# subdir('intl') # Internationalization stuff -- This call was moved to the gettext block above.
subdir('po')   # Localization files
subdir('lib')  # Processes lib/meson.build. This makes 'libmydnsutil' available via meson.override_dependency().
libmydnsutil_dep = dependency('libmydnsutil') # Now it can be resolved.

# Process src/lib before src
subdir('src/lib') # Processes src/lib/meson.build. This makes 'libmydns' available.
lib_mydns_dep = dependency('libmydns') # Now it can be resolved.

# src subdir depends on libmydnsutil_dep and lib_mydns_dep.
# These dependencies will be available to src/meson.build
# because they are defined in the parent scope.
subdir('src')  # Main source code for executables
subdir('doc')  # Documentation


# Message to user
project_options_summary = {
  'Database': db_name,
  'OpenSSL': use_openssl_opt.to_string(),
  'Profiling': get_option('enable-profiling').to_string(),
  'Debug': get_option('enable-debug').to_string(),
  'Valgrind': get_option('enable-valgrind').to_string(),
  'Strict Warnings': get_option('enable-strict').to_string(),
  'Status Opcode': get_option('enable-status').to_string(),
  'Date Logging Disabled': get_option('disable-date-logging').to_string(),
  'David Phillips Aliasing': get_option('enable-alias').to_string()
}
summary_message = '\nMyDNS ' + meson.project_version() + ' configured with:\n'
foreach name, val : project_options_summary
  summary_message += '  ' + name + ': ' + val + '\n'
endforeach
summary_message += '\nType "meson compile" to build, then "meson install" to install.'
message(summary_message)


# Installation of default configuration file (replicates 'make conf')
# This script is run during 'meson install'.
# It needs the path to the installed 'mydns' executable and the target config file path.

# Construct paths for the install script arguments.
# MESON_INSTALL_PREFIX is available to install scripts, so paths should be relative to that or absolute.
# However, add_install_script arguments are evaluated at Meson configure time.
# We need to give it paths that will be correct *after* installation.
# get_option('prefix') gives the configured prefix.
# sbindir and sysconfdir are relative to prefix unless absolute.

# Path to the mydns executable *after* it's installed.
# This assumes 'mydns' is the name of the executable from src/mydns/meson.build.
mydns_exe_name = 'mydns' # Name of the executable
sbindir_abs = get_option('prefix') / get_option('sbindir')
mydns_exe_installed_path = sbindir_abs / mydns_exe_name

# Path where mydns.conf should be installed.
sysconfdir_abs = get_option('prefix') / get_option('sysconfdir')
mydns_conf_install_path = sysconfdir_abs / 'mydns.conf'

meson.add_install_script('build-aux/install_conf.py', mydns_exe_installed_path, mydns_conf_install_path)

# 'make localconf' functionality: run mydns --dump-config
# This run_target uses the *installed* path of the mydns executable.
# It will only work correctly after 'meson install' or if 'mydns' is in PATH and points to the correct version.
run_target('localconf',
  command : [mydns_exe_installed_path, '--dump-config'],
  # No explicit build dependency, as it relies on the installed executable.
  # This target is more of a post-install convenience.
  description: 'Run mydns --dump-config (uses configured installed path; run after "meson install")'
)

# Add a note about QUICKSTART files and new commands
message('\n---------------------\nMyDNS Build Information:\n---------------------')
message('Quickstart guides available in source: QUICKSTART.mysql, QUICKSTART.postgres')
message('Default configuration file (mydns.conf) will be generated by "meson install" in ' + mydns_conf_install_path + ' if not present.')
message('To dump config locally (e.g. for testing):')
message('  - After install: Run "meson run localconf" or "' + mydns_exe_installed_path + ' --dump-config"')
message('  - From build dir (example): "<build_dir>/src/mydns/mydns --dump-config"')
message('    (Exact path to built executable might vary based on build configuration)')
