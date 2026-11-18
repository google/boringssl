---
name: update-wycheproof-test-vectors
description: How to import updated Project Wycheproof test vectors and regenerate BoringSSL's FileTest inputs.
---

# Updating Wycheproof Test Vectors

**Note**: Handling new tests, upstream JSON fields, or `acceptable` test flags requires judgment. Do a first pass on these decisions, call out **all** such decisions explicitly in your output to the user along with a concise justification for your first-pass decision, and wait for the human user's decision on anything genuinely questionable.

1.  **Sync Upstream JSON Vectors**:
    *   Sync `testvectors_v1/*.json` from the target revision of the upstream github.com repository recorded in [third_party/wycheproof_testvectors/METADATA](../../../third_party/wycheproof_testvectors/METADATA) into `third_party/wycheproof_testvectors/` (including additions and deletions).

2.  **Convert Implemented Test Vectors to `.txt`**:
    *   Only convert and import into BoringSSL's test suite (`defaultInputs` in [util/convert_wycheproof/convert_wycheproof.go](../../../util/convert_wycheproof/convert_wycheproof.go) and `*_test.cc`) test vectors for primitives and formats implemented in BoringSSL (checking both new upstream files and whether BoringSSL now implements anything previously skipped). Note any omissions in the CL description.
    *   When invoked with no arguments, `convert_wycheproof.go` reads `defaultInputs` from and writes `.txt` files to CWD:
        ```bash
        (cd third_party/wycheproof_testvectors && go run ../../util/convert_wycheproof/convert_wycheproof.go)
        ```
    *   If `.txt` files are added or removed (or `defaultInputs` changes), run [update_pregenerated_files](../update_pregenerated_files/SKILL.md).

3.  **Update [METADATA](../../../third_party/wycheproof_testvectors/METADATA)**: Update `version` and `last_upgrade_date`.

4.  **Build and Triage**:
    *   Build and run `crypto_test` (see [build_and_test](../build_and_test/SKILL.md)).
    *   Update `convert_wycheproof.go` or `*_test.cc` consumers as needed for new tests, upstream fields, or `acceptable` test flags (see [crypto/test/wycheproof_util.h](../../../crypto/test/wycheproof_util.h)), following the judgment and reporting note above.
