# po/meson.build

# Use Meson's internationalization module
i18n = import('i18n')

# From po/POTFILES.in, these are the source files that contain translatable strings
# Paths are relative to the Meson project root.
pot_sources = [
  'src/lib/sql.c',
  'src/mydns/alias.c',
  'src/mydns/axfr.c',
  'src/mydns/cache.c',
  'src/mydns/conf.c',
  'src/mydns/data.c',
  'src/mydns/db.c',
  'src/mydns/error.c',
  'src/mydns/listen.c',
  'src/mydns/main.c',
  'src/mydns/queue.c',
  'src/mydns/recursive.c',
  'src/mydns/reply.c',
  'src/mydns/resolve.c',
  'src/mydns/rr.c',
  'src/mydns/status.c',
  'src/mydns/task.c',
  'src/mydns/tcp.c',
  'src/mydns/udp.c',
  'src/mydns/update.c',
  'src/util/check.c',
  'src/util/conf.c',
  'src/util/export.c',
  'src/util/import-axfr.c',
  'src/util/import-tinydns.c',
  'src/util/import.c',
  'src/util/ptrconvert.c',
  'src/util/util.c',
  'lib/conf.c',
  'lib/error.c',
  'lib/getopt.c',
  'lib/passinput.c'
]

# The name of the .pot file and the installed .mo files.
package_name = 'mydns'

# LINGUAS file lists available languages: es fr pt_BR
# These files (es.po, fr.po, pt_BR.po) should exist in this directory (po/)
languages = ['es', 'fr', 'pt_BR']

# Generate .po files from .pot (if needed, typically .po are maintained by translators)
# And compile .po files to .mo files
i18n.gettext(package_name,
  preset: 'gnu', # Use gnu gettext conventions
  languages: languages,
  sources: pot_sources,
  install: true
  # install_dir by default is get_option('localedir') / project_name / 'LC_MESSAGES'
  # For package_name 'mydns', this becomes <prefix>/<datadir>/locale/<lang>/LC_MESSAGES/mydns.mo
  # This matches standard GNU gettext layout.
)

# Meson automatically creates targets:
# `meson compile mydns-pot` to generate mydns.pot
# `meson compile mydns-update-po` to update .po files from mydns.pot
# `meson compile mydns-mo` to compile .mo files (also done during normal compile)
