---
name: update-bazel-deps
description: How to update Bazel module dependencies in MODULE.bazel.
---

# Updating Bazel Dependencies (`MODULE.bazel`)

Run [util/update_bazel_deps.go](../../../util/update_bazel_deps.go) from the repository root (requires `go` and `bazelisk` on `PATH`) to update `bazel_dep` versions and lockfiles in `.` and `util/bazel-example`:

```bash
go run ./util/update_bazel_deps.go
```

Then verify both workspaces:

```bash
bazelisk test //...
(cd util/bazel-example && bazelisk build //...)
```

(See [docs/releasing.md](../../../docs/releasing.md) for cutting a new BoringSSL BCR release, and [update_bot_deps](../update_bot_deps/SKILL.md) for updating the pinned Bazel version in `.bazelversion` and `util/bot/DEPS`.)
