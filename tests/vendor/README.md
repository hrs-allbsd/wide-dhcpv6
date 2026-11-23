# Test tool sources

The archives are unmodified upstream release sources. `SHA256` pins their
contents. The Kyua, ATF, and Lutok versions match the imports under `contrib/`
in the FreeBSD source snapshot used by this project (`24e09265f924`).
Upstream release archives include the portable configure scripts. The
FreeBSD import uses the FreeBSD build framework.

| Source | Release | License notice in the archive |
| --- | --- | --- |
| [Kyua](https://github.com/freebsd/kyua/releases/tag/kyua-0.15.2) | 0.15.2 | `LICENSE` and individual source notices |
| [ATF](https://github.com/freebsd/atf/releases/tag/atf-0.26) | 0.26 | `COPYING` and individual source notices |
| [Lutok](https://github.com/freebsd/lutok/releases/tag/lutok-0.6.2) | 0.6.2 | `COPYING` and individual source notices |
| [Lua](https://www.lua.org/ftp/lua-5.4.8.tar.gz) | 5.4.8 | MIT license in `doc/readme.html` |
| [SQLite](https://www.sqlite.org/2026/sqlite-autoconf-3540100.tar.gz) | 3.54.1 | Public-domain SQLite source notices and separate licenses for build tooling |

When updating a source, check the upstream license notices and release checksum,
update `SHA256` and the build script, then run the suite on FreeBSD and Linux.

On FreeBSD the build applies `kyua-0.15.2-freebsd-jail-string.patch` to supply
the declarations for `strlen()` and `strerror()` in Kyua's jail backend.
