# Public Suffix List snapshot

`public_suffix_list.dat` is a pinned snapshot of the Public Suffix List installed
by the Debian `publicsuffix` package on 2023-09-30.

- SHA-256: `02074b85e6f1454055b82aa7812bcea05f6afd9076e9a60ae1eb30ad61a26881`
- Upstream: <https://publicsuffix.org/list/public_suffix_list.dat>
- License: Mozilla Public License 2.0, as declared in the data file header.

PacketQuapture embeds this exact data file at build time. Updating it is an explicit
source change that must update the hash, tests and analytics version notes.
