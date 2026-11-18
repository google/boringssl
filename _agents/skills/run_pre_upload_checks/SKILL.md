---
name: run-pre-upload-checks
description: How to run local presubmit, formatting, filename, and documentation checks before uploading a BoringSSL change.
---

# Running Pre-Upload Checks

Run the applicable local checks below before uploading a change, in addition to [build_and_test](../build_and_test/SKILL.md).

## CQ-Enforced Checks (Blocking)

*   **Pre-generated files**: Check that `gen/` is up-to-date (see [update_pregenerated_files](../update_pregenerated_files/SKILL.md), with `clang` on `PATH`).
*   **Source filename uniqueness** (when adding/renaming `.c`/`.cc` files): Run `go run ./util/check_filenames.go` (see [util/check_filenames.go](../../../util/check_filenames.go)).
*   **Public header docs** (when modifying `include/openssl/*.h`): Run `(cd util && go run doc.go -out /tmp/bssl-docs)` ([util/doc.go](../../../util/doc.go) reads `doc.config` and `doc.css` from CWD and defaults `-out` to `.`).
*   **Go unit tests** (when modifying Go packages): Run `go test $(cat util/go_tests.txt)`.

## Style and Presubmit Checks (Non-Blocking on CQ)

These checks (including [PRESUBMIT.py](../../../PRESUBMIT.py)) are not enforced by CQ; run them when available locally, and treat missing local tools as non-blocking:

*   **C/C++ formatting** (outside `third_party/` and `gen/`): `git clang-format`
*   **Bazel formatting** (`*.bazel` / `*.bzl` outside `third_party/` and `gen/`): `buildifier --mode=check <files...>`
*   **LUCI CQ config** (when modifying `infra/config/main.star`): Follow [infra/config/README.md](../../../infra/config/README.md).
