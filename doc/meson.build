# doc/meson.build

# Man pages
# man_MANS = mydns.8 mydnscheck.8 mydns.conf.5 mydns-conf.8 mydnsexport.8 mydnsimport.8 mydnsptrconvert.8
man_pages_in = [
  'mydns.8.in',
  'mydnscheck.8.in',
  'mydns.conf.5.in',
  'mydns-conf.8.in',
  'mydnsexport.8.in',
  'mydnsimport.8.in',
  'mydnsptrconvert.8.in'
]
man_pages_out = [
  'mydns.8',
  'mydnscheck.8',
  'mydns.conf.5',
  'mydns-conf.8',
  'mydnsexport.8',
  'mydnsimport.8',
  'mydnsptrconvert.8'
]

# Texinfo
# info_TEXINFOS = mydns.texi
# mydns_TEXINFOS = configuration.texi database.texi fdl.texi installation.texi introduction.texi references.texi server.texi texinfo.tex troubleshooting.texi utilities.texi
# texinfo.tex is a standard file, usually not listed as a source for mydns.texi itself but included by it.
# The main texi file is mydns.texi
texinfo_main_file = 'mydns.texi'
# These are its dependencies (files included by mydns.texi)
# Meson's texinfo functions might not explicitly need these listed if mydns.texi includes them correctly.
# However, if they change, mydns.texi should be rebuilt.
# For now, we assume mydns.texi is the primary input.
texinfo_sources = [
  texinfo_main_file,
  'configuration.texi',
  'database.texi',
  'fdl.texi',
  'installation.texi',
  'introduction.texi',
  'references.texi',
  'server.texi',
  # 'texinfo.tex', # Usually not a direct source for the main file's compilation to info
  'troubleshooting.texi',
  'utilities.texi',
  'version.texi' # This one is important as it's generated/updated
]


# Replicate sed substitutions for version information.
doc_conf_data = configuration_data()

# Set project-specific details. These should ideally come from the root project.
# Meson subprojects don't automatically inherit all parent project variables directly into `meson.project_...()`.
# We are in 'mydns_doc', so meson.project_name() is 'mydns_doc'.
# We must get these from the main project's configuration data or options.
# The root `meson.build` already prepares these for `config.h`.
# We can re-use those values if they are accessible here.
# For simplicity, we'll use the values that should be in config.h or are project-global.
# This assumes `get_option` can access root-level options for paths.
# For package name/version, we directly use the known root project values.

doc_conf_data.set_quoted('MYDNS_CONF', get_option('sysconfdir') / 'mydns.conf') # From root meson_options
doc_conf_data.set_quoted('PACKAGE_DATE', 'N/A in Meson build') # Autotools had this, Meson does not by default
doc_conf_data.set_quoted('PACKAGE_NAME', 'mydns')      # Root project's name
doc_conf_data.set_quoted('PACKAGE_VERSION', '1.1.0')  # Root project's version
doc_conf_data.set_quoted('PACKAGE_STRING', 'mydns 1.1.0') # Root project's string
doc_conf_data.set_quoted('PACKAGE_AUTHOR', 'Don Moore <bboy@bboy.net>')
doc_conf_data.set_quoted('PACKAGE_BUGREPORT', 'bboy@bboy.net')
doc_conf_data.set_quoted('PACKAGE_URL', 'http://mydns.bboy.net') # Corrected from HOMEPAGE
doc_conf_data.set_quoted('PACKAGE_COPYRIGHT', 'Copyright (C) 2002-2005 Don Moore')


man_install_dir = get_option('mandir') # From built-in options
man_section_map = {
  'mydns.8': 'man8',
  'mydnscheck.8': 'man8',
  'mydns.conf.5': 'man5',
  'mydns-conf.8': 'man8',
  'mydnsexport.8': 'man8',
  'mydnsimport.8': 'man8',
  'mydnsptrconvert.8': 'man8'
}

# Process man pages
foreach idx : range(man_pages_in.length())
  man_in_filename = man_pages_in[idx]
  man_out_filename = man_pages_out[idx]

  # Check if the .in file exists before trying to configure it
  if run_command('test', '-f', files(man_in_filename)[0]).returncode() != 0
    message('Man page source file ' + man_in_filename + ' not found. Skipping.')
    continue
  endif

  man_file_configured = configure_file(
    input : man_in_filename,
    output : man_out_filename, # Output name for build directory
    configuration : doc_conf_data,
    # Meson's configure_file doesn't support the `tr -s '\n'` part. This is usually fine.
  )

  section = man_section_map.get(man_out_filename, 'man1') # Default to man1 if not found
  install_man(man_file_configured, install_dir : man_install_dir / section)
endforeach

# Texinfo processing

# Configure version.texi if version.texi.in exists
# This file typically contains @set PACKAGE_VERSION ... etc.
configured_version_texi = ''
version_texi_in_path = 'version.texi.in'
if run_command('test', '-f', files(version_texi_in_path)[0]).returncode() == 0
  configured_version_texi = configure_file(
    input: version_texi_in_path,
    output: 'version.texi', # This will be in the build directory
    configuration: doc_conf_data
  )
  message('Configured version.texi from version.texi.in')
else
  message('File "version.texi.in" not found. Texinfo output might not have correct version info unless "version.texi" is already correct or mydns.texi does not rely on it for version macros.')
  # If version.texi.in doesn't exist, but version.texi does, we use the existing one.
  if run_command('test', '-f', files('version.texi')[0]).returncode() == 0
     configured_version_texi = files('version.texi')[0] # Use existing source file
  else
     configured_version_texi = '' # No version.texi available
  endif
endif

# Find makeinfo
makeinfo = find_program('makeinfo', required : false)
if makeinfo.found() and run_command('test', '-f', files(texinfo_main_file)[0]).returncode() == 0
  # Ensure the main texi file exists

  # Define dependencies for the custom target.
  # If version.texi was configured, it's a generated file (in build dir).
  # Other texi files are sources.
  current_texinfo_deps = []
  foreach src_file : texinfo_sources
    if src_file == 'version.texi' and configured_version_texi != '' and configured_version_texi != files('version.texi')[0]
      # If version.texi was generated from version.texi.in, depend on the generated one.
      current_texinfo_deps += configured_version_texi
    elif run_command('test', '-f', files(src_file)[0]).returncode() == 0
      current_texinfo_deps += files(src_file) # Depend on existing source file
    endif
  endforeach

  # Check if main input file exists
  main_texi_file_obj = files(texinfo_main_file)[0]

  info_file_target = custom_target('mydns_info',
    input : main_texi_file_obj, # mydns.texi (source dir)
    output : 'mydns.info',    # The output file (build dir)
    # All .texi files are dependencies for the info generation
    depends : current_texinfo_deps, # Ensure rebuild if any .texi file changes. Use `depends` for generated files.
                                   # `depend_files` is for static files.
    # Makeinfo needs to find included files. -I . (for current dir in build) and -I @SOURCE_ROOT@/doc (for source dir)
    # command : [makeinfo, '-I', meson.current_source_dir(), '-I', meson.current_build_dir(), '--output=@OUTPUT@', '@INPUT@'],
    command : [makeinfo, '-I', meson.current_source_dir(), '-I', meson.current_build_dir(), '--no-validate', '--output=@OUTPUT@', '@INPUT@'], # Added --no-validate for common issues
    build_by_default : true,
    install : true,
    install_dir : get_option('infodir') # From built-in options
  )

  # HTML generation
  texi2html = find_program('texi2html', required : false)
  if texi2html.found()
    html_target = custom_target('mydns_html_doc', # Renamed target to avoid conflict if mydns.html is an output name
      input : main_texi_file_obj,
      output : 'mydns_html_output', # This will be a directory
      depends : current_texinfo_deps,
      # texi2html behavior varies; some output to current dir, some to specified dir.
      # Using @OUTDIR@ to make it put files into the 'mydns_html_output' directory.
      command : [texi2html, '--output=@OUTDIR@', '@INPUT@'],
      build_by_default : true, # Build it by default
      install : true,
      install_dir : get_option('docdir') / 'mydns-html' # Install the directory
    )
  else
    message('texi2html not found, HTML documentation will not be built.')
  endif

else
  if not makeinfo.found()
    message('makeinfo not found, Texinfo documentation (.info, .html) will not be built.')
  else
    message('Main texinfo file ' + texinfo_main_file + ' not found. Texinfo documentation cannot be built.')
  endif
endif

# Note: Hardcoded package name/version for doc_conf_data to root project's values.
# Corrected PACKAGE_URL to use 'http://mydns.bboy.net' as in root.
# Added checks for file existence before processing for man and texi.
# Refined makeinfo command with include paths and --no-validate.
# Changed texi2html output to a directory and enabled install.
