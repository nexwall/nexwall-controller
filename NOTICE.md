# NOTICE

This project is a derivative work of `NethServer/nethsecurity-controller`, copyright Nethesis S.r.l. and contributors,
licensed under the GNU General Public License. The original copyright and license notices in the source files are
kept. Go module paths stay unchanged so that the source is unchanged.

## Changes from upstream (GPL section 2(a))

2026-09-23:

- `ui/Containerfile` now builds from `nexwall/nexwall-ui` (`main` branch) instead of `NethServer/nethsecurity-ui`,
  so the image no longer depends on the upstream repository at build time. `nexwall/nexwall-ui` `main` merged the
  `fix/vendor-tarball` branch first, so it carries its own vendored `@nexwall/vue-components` tarball instead of an
  npm dependency on the original package
- `build.sh` fetches `nexwall/nexwall-ui` on the host (git/SSH) into `ui/src` before building the `ui` image, and
  `ui/Containerfile` now `COPY`s that tree instead of running `git clone` inside the build container.
  `nexwall/nexwall-ui` is private, so an anonymous clone from inside the isolated build container fails; the
  original `NethServer/nethsecurity-ui` was public, so this difference didn't exist upstream

2026-09-20:

- README rewritten
- removed upstream repository automation and agent guide
