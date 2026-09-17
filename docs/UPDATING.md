# DuckDB version support

PacketQuapture uses DuckDB's internal C++ extension API, so every distributed binary is tied to an exact DuckDB
version and platform.

## Automatic releases

The `Publish New DuckDB Release` workflow checks daily for the newest stable DuckDB release. When it finds an
unpublished version, it builds and tests that exact tag across the complete native platform matrix. A successful run
publishes a `duckdb-vX.Y.Z` GitHub Release with platform-labelled binaries, compressed copies, and SHA-256 checksums.
Any build or test failure prevents publication.

The `DuckDB Main Compatibility` workflow also tests Linux weekly against DuckDB `main`, providing advance warning of
internal API changes before they reach a stable release.

## Advancing the development baseline

After an automated release succeeds:

1. Set `.github/duckdb-version` to the new DuckDB tag.
2. Check out that tag in the `duckdb` submodule.
3. Check out the corresponding release branch or tag in the `extension-ci-tools` submodule.
4. Run a clean debug build and `test/sql/read_pcap.test` locally.
5. Commit the version file and both submodule pointers together.

If the release workflow fails, do not publish manually until the extension has been adapted and the complete matrix
passes. Useful references are DuckDB's [release notes](https://github.com/duckdb/duckdb/releases),
[extension distribution documentation](https://duckdb.org/docs/stable/extensions/extension_distribution), and the
[core extension patch history](https://github.com/duckdb/duckdb/commits/main/.github/patches/extensions).
