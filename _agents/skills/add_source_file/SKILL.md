---
name: add-source-file
description: How to add a new source file to the BoringSSL build.
---

# Adding a Source File to the Build

## Steps

1.  **Check Filename Uniqueness** (for `.c`/`.cc` files):
    *   Verify unique basenames with `go run ./util/check_filenames.go` (see [util/check_filenames.go](../../../util/check_filenames.go)).

2.  **Update `build.json` (if not already matched by a glob)**:
    *   Add the file to the appropriate target and section (`srcs`, `hdrs`, `internal_hdrs`, `data`, etc.) in [build.json](../../../build.json) (schema in [util/pregenerate/build.go](../../../util/pregenerate/build.go)).
    *   Files matching an existing wildcard glob in `build.json` (e.g., `fuzz/*.cc`, `rust/bssl-*/src/*.rs`, and globbed test `data` paths) do not require editing `build.json`, but still require step 3.

3.  **Update Pregenerated Files**:
    *   Regenerate `gen/` using [update_pregenerated_files](../update_pregenerated_files/SKILL.md) (required even when adding a file matched by an existing glob).
