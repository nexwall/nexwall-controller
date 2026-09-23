# NOTICE

This project is a derivative work of `NethServer/nethsecurity-controller`, copyright Nethesis S.r.l. and contributors,
licensed under the GNU General Public License. The original copyright and license notices in the source files are
kept. Go module paths stay unchanged so that the source is unchanged.

## Changes from upstream (GPL section 2(a))

2026-09-23:

- `ui/Containerfile` now builds from `nexwall/nexwall-ui` instead of `NethServer/nethsecurity-ui`, pinned to tag
  `v2.24.1-nexwall.7`, so the image no longer depends on the upstream repository at build time.
  `nexwall/nexwall-ui` carries its own vendored `@nexwall/vue-components` tarball instead of an npm dependency on
  the original package

2026-09-20:

- README rewritten
- removed upstream repository automation and agent guide
