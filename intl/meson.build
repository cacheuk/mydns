# intl/meson.build
project('mydns_intl_fallback', 'c')
cc = meson.get_compiler('c')

# This option is defined in the root meson_options.txt
build_internal_gettext_opt = get_option('internal_gettext')

# Try to find system libintl
system_libintl_dep = dependency('libintl', required : false)

# This will hold the dependency for our internal libintl if we build it
internal_intl_lib_dep = disabler()

if build_internal_gettext_opt and not system_libintl_dep.found()
  message('System libintl not found and internal_gettext=true. Building internal gettext compatibility library from intl/')

  intl_sources = [
    'bindtextdom.c',
    'dcgettext.c',
    # 'dcngettext.c', # Assuming not used based on typical minimal gettext fallbacks
    'dgettext.c',
    # 'dngettext.c',  # Assuming not used
    'explodename.c',
    'finddomain.c',
    'gettext.c',
    'intl-compat.c',
    'l10nflist.c',
    'loadmsgcat.c',
    'localcharset.c',
    'localealias.c',
    'localename.c',
    'ngettext.c',
    'plural.c',     # Assuming pre-generated or simple version if plural.y is complex
    'textdomain.c'
    # Headers like eval-plural.h, libgnuintl.h, loadinfo.h, plural-exp.h are included by .c files
  ]

  # Note: Generation of plural.c from plural.y using bison is omitted for simplicity.
  # If plural.y exists and is critical, bison would need to be added as a build tool.
  # We assume plural.c is either provided or the version included is sufficient.

  # Check for essential source files to exist before attempting to compile
  existing_sources = []
  foreach s_file : intl_sources
    if run_command('test', '-f', files(s_file)[0]).returncode() == 0
      existing_sources += s_file
    else
      warning('Source file @0@ not found in intl/ directory, skipping.'.format(s_file))
    endif
  endforeach

  if existing_sources.length() == 0
    error('No source files found for internal gettext library. Cannot proceed if internal_gettext is enabled and system libintl is missing.')
  endif

  libmydns_intl_fallback = static_library('mydnsintlfallback',
    existing_sources,
    include_directories : include_directories('.'), # For its own headers like libgnuintl.h, localealias.h etc.
    c_args : ['-DIN_LIBINTL'], # A common define for such internal gettext libraries
    install : false # This is an internal fallback library, not for direct installation
  )

  internal_intl_lib_dep = declare_dependency(
    link_with : libmydns_intl_fallback,
    include_directories : include_directories('.') # To provide e.g. libgnuintl.h (hopefully as libintl.h for project sources)
                                                 # or project sources include "libgnuintl.h" directly.
                                                 # For a true drop-in, libgnuintl.h might need to be named libintl.h
                                                 # or a wrapper provided. For now, assume sources can find what they need.
  )

  # Override the 'libintl' dependency. Any subsequent call to dependency('libintl')
  # in the main project or other subprojects will resolve to this internal library.
  meson.override_dependency('libintl', internal_intl_lib_dep)

  # Data files needed by this internal gettext implementation.
  # These are typically installed in $(datadir)/locale.
  # The Autotools build installed config.charset and locale.alias.
  # Check if they exist before trying to install.
  if run_command('test', '-f', files('config.charset')[0]).returncode() == 0
    install_data('config.charset', install_dir : get_option('datadir') / 'locale')
  endif
  if run_command('test', '-f', files('locale.alias')[0]).returncode() == 0
    install_data('locale.alias', install_dir : get_option('datadir') / 'locale')
  endif

  message('Internal gettext library built and will be used.')

elif build_internal_gettext_opt and system_libintl_dep.found()
  message('Internal gettext build was enabled, but system libintl was found. System libintl will be used.')
else
  # Either internal build not enabled, or system libintl found (covered above)
  message('Internal gettext library not built (internal_gettext=false or system libintl found).')
endif

# If this subproject doesn't build the internal library, it provides no dependencies.
# The key is the meson.override_dependency() call when it *does* build the library.
