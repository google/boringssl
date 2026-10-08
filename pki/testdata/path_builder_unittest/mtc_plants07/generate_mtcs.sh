#!/bin/bash

set -e -x

mkdir out

go run github.com/ietf-plants-wg/merkle-tree-certs/demo@bfb754ff821153176667a9b9a06f08703f134728 generate -config=mtc-config.json -out=out

mv -v out/cert_0_0.pem mtc-ica.pem
mv -v out/cert_1_0.pem mtc-leaf.pem
mv -v out/cert_1_1.pem mtc-leaf-standalone.pem
mv -v out/cert_1_2.pem mtc-leaf-standalone-3cosigners.pem
mv -v out/cert_1_3.pem mtc-leaf-standalone-no_ca_signer.pem
mv -v out/cert_1_4.pem mtc-leaf-standalone-duplicate_ca_signer.pem
mv -v out/cert_1_5.pem mtc-leaf-standalone-cosigner_wrong_order.pem
rm -r out

