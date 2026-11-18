---
name: update-go-deps
description: How to update Go module dependencies in go.mod and go.sum.
---

# Updating Go Dependencies (`go.mod`)

1.  **Update Modules and Tidy**:
    *   From the repository root, update a specific module (`go get example.com/pkg@latest`) or all dependencies:
        ```bash
        go get -u ./...
        go mod tidy
        ```
    *   Ensure `go get` did not raise the `go` directive in [go.mod](../../../go.mod) above `go_version` in [util/bot/DEPS](../../../util/bot/DEPS) (see [update_bot_deps](../update_bot_deps/SKILL.md)).

2.  **Verify**:
    ```bash
    go test $(cat util/go_tests.txt)
    go build ./util/fipstools/acvp/acvptool
    ```
    Also run pregeneration checks (see [update_pregenerated_files](../update_pregenerated_files/SKILL.md)) and the SSL runner (see [run_ssl_go_tests](../run_ssl_go_tests/SKILL.md)).
