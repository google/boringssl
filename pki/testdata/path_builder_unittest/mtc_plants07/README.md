# MTC test certs

This directory contains the following certs:

- `mtc-leaf.pem`
  - signatureless MTC issued by an MTC CA
- `mtc-leaf-standalone.pem`
  - standalone MTC issued by an MTC CA
- `mtc-leaf-standalone-3cosigners.pem`
  - standalone MTC containing the CA cosignature and two other cosignatures.
- `mtc-leaf-standalone-no_ca_signer.pem`
  - MTC containing one cosignature, but no CA cosignature.
- `mtc-leaf-standalone-duplicate_ca_signer.pem`
  - standalone MTC containing two duplicate CA cosignatures.
- `mtc-leaf-standalone-cosigner_wrong_order.pem`
  - standalone MTC containing the CA cosignature and another cosignature, but
    the cosignatures are not in sorted order.
- `mtc-ica.pem`
  - signatureless MTC issued by the same MTC CA
  - its BasicConstraints has `cA=TRUE`
- `leaf.pem`
  - classical ECDSA cert (SPKI) with ECDSA `signatureAlgorithm`
  - issued by `mtc-ica.pem`

## (Re)generating test certs

Generating these certs is done in two steps.

The first step is to generate a keypair for the ICA and use the private key to
sign the leaf cert:

1. Run `go run generate_leaf.go`
2. Copy the certificate PEM to `leaf.pem`
3. Copy the ICA SPKI base64 to the first `PublicKey` entry in `mtc-config.json`

The next step is to generate the MTCs:

1. Run `generate_mtcs.sh`
2. Copy the subtree range and hash from the script output into
PathBuilderMTCPlants07Test::SetUp.
