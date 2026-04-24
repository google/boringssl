# MTC test cert generation

The following test certs are created according to these instructions.

## Certs

- `mtc-leaf.pem`
- `mtc-leaf-bitflip.pem`
  - a copy of `mtc-leaf.pem`, but with a bitflip in its inclusion proof
- `mtc-leaf-b.pem`
- `mtc-leaf-c.pem`

## Instructions

- Run
  `go run github.com/ietf-plants-wg/merkle-tree-certs/demo@b0c83104918f10e8c813783f77434143eab4ef97 -config=mtc-config.json`
- copy/move the following output files:
  - `out/cert_9_0.pem` to `mtc-leaf.pem`
  - `out/cert_9_1.pem` to `mtc-leaf-bitflip.pem`
  - `out/cert_9_2.pem` to `mtc-leaf-unused-bit.pem`
  - `out/cert_10_0.pem` to `mtc-leaf-b.pem`
  - `out/cert_19_0.pem` to `mtc-leaf-c.pem`
- edit `VerifyMTCTest::SetUp` to set the trusted subtrees to the ones output by
  the above command.
- remove other artifacts created by the merkle-tree-certs/demo tool (e.g.
  `rm -r out`).