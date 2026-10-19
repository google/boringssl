// Copyright 2020 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build ignore

// make_policy_certs.go generates certificates for testing policy handling.
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"math/big"
	"os"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var resetFlag = flag.Bool("reset", false, "if set, regenerates certificates that already exist")

var (
	// https://davidben.net/oid
	testOID1 = must(x509.OIDFromInts([]uint64{1, 2, 840, 113554, 4, 1, 72585, 2, 1}))
	testOID2 = must(x509.OIDFromInts([]uint64{1, 2, 840, 113554, 4, 1, 72585, 2, 2}))
	testOID3 = must(x509.OIDFromInts([]uint64{1, 2, 840, 113554, 4, 1, 72585, 2, 3}))
	testOID4 = must(x509.OIDFromInts([]uint64{1, 2, 840, 113554, 4, 1, 72585, 2, 4}))
	testOID5 = must(x509.OIDFromInts([]uint64{1, 2, 840, 113554, 4, 1, 72585, 2, 5}))

	// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4
	certificatePoliciesOID = asn1.ObjectIdentifier([]int{2, 5, 29, 32})
	anyPolicyOID           = must(x509.OIDFromInts([]uint64{2, 5, 29, 32, 0}))

	// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.5
	policyMappingsOID = asn1.ObjectIdentifier([]int{2, 5, 29, 33})

	// https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.11
	policyConstraintsOID = asn1.ObjectIdentifier([]int{2, 5, 29, 36})
)

var leafKey, intermediateKey, rootKey *ecdsa.PrivateKey

func init() {
	leafKey = mustParseECDSAKey(leafKeyPEM)
	intermediateKey = mustParseECDSAKey(intermediateKeyPEM)
	rootKey = mustParseECDSAKey(rootKeyPEM)
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func addOID(b *cryptobyte.Builder, oid x509.OID) {
	b.AddASN1(cbasn1.OBJECT_IDENTIFIER, func(child *cryptobyte.Builder) {
		child.AddBytes(must(oid.MarshalBinary()))
	})
}

type templateAndKey struct {
	template x509.Certificate
	key      *ecdsa.PrivateKey
}

func mustGenerateCertificate(path string, subject, issuer *templateAndKey) {
	if !*resetFlag {
		// Skip if the file already exists.
		_, err := os.Stat(path)
		if err == nil {
			return
		}
		if !os.IsNotExist(err) {
			panic(err)
		}
	}
	cert := must(x509.CreateCertificate(rand.Reader, &subject.template, &issuer.template, &subject.key.PublicKey, issuer.key))
	file := must(os.Create(path))
	defer file.Close()
	err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err != nil {
		panic(err)
	}
}

func main() {
	flag.Parse()

	notBefore := must(time.Parse(time.RFC3339, "2000-01-01T00:00:00Z"))
	notAfter := must(time.Parse(time.RFC3339, "2100-01-01T00:00:00Z"))

	root2 := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(1),
			Subject:               pkix.Name{CommonName: "Policy Root 2"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		},
		key: rootKey,
	}
	root := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(1),
			Subject:               pkix.Name{CommonName: "Policy Root"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
		},
		key: rootKey,
	}
	intermediate := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(2),
			Subject:               pkix.Name{CommonName: "Policy Intermediate"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  true,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
			Policies:              []x509.OID{testOID1, testOID2},
		},
		key: intermediateKey,
	}
	leaf := templateAndKey{
		template: x509.Certificate{
			SerialNumber:          new(big.Int).SetInt64(3),
			Subject:               pkix.Name{CommonName: "www.example.com"},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			BasicConstraintsValid: true,
			IsCA:                  false,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:              x509.KeyUsageCertSign,
			SignatureAlgorithm:    x509.ECDSAWithSHA256,
			DNSNames:              []string{"www.example.com"},
			Policies:              []x509.OID{testOID1, testOID2},
		},
		key: leafKey,
	}

	// Generate a valid certificate chain from the templates.
	mustGenerateCertificate("policy_root.pem", &root, &root)
	mustGenerateCertificate("policy_intermediate.pem", &intermediate, &root)
	mustGenerateCertificate("policy_leaf.pem", &leaf, &intermediate)

	// root2 is used for tests that need a longer chain, using a Root/Root2
	// cross-sign as one of the certificates.
	mustGenerateCertificate("policy_root2.pem", &root2, &root2)

	// Introduce syntax errors in the leaf and intermediate.
	leafInvalid := leaf
	leafInvalid.template.Policies = nil
	leafInvalid.template.ExtraExtensions = []pkix.Extension{{Id: certificatePoliciesOID, Value: []byte("INVALID")}}
	mustGenerateCertificate("policy_leaf_invalid.pem", &leafInvalid, &root)

	intermediateInvalid := intermediate
	intermediateInvalid.template.Policies = nil
	intermediateInvalid.template.ExtraExtensions = []pkix.Extension{{Id: certificatePoliciesOID, Value: []byte("INVALID")}}
	mustGenerateCertificate("policy_intermediate_invalid.pem", &intermediateInvalid, &root)

	// Duplicates are not allowed in certificatePolicies.
	leafDuplicate := leaf
	leafDuplicate.template.Policies = []x509.OID{testOID1, testOID2, testOID2}
	mustGenerateCertificate("policy_leaf_duplicate.pem", &leafDuplicate, &root)

	intermediateDuplicate := intermediate
	intermediateDuplicate.template.Policies = []x509.OID{testOID1, testOID2, testOID2}
	mustGenerateCertificate("policy_intermediate_duplicate.pem", &intermediateDuplicate, &root)

	// Various policy constraints with requireExplicitPolicy values. Although
	// Go supports this extension, CreateCertificate cannot serialize it. See
	// http://go.dev/issue/82347
	b := cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		seq.AddASN1Int64WithTag(0, cbasn1.Tag(0).ContextSpecific())
	})
	requireExplicitPolicy0 := b.BytesOrPanic()

	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		seq.AddASN1Int64WithTag(1, cbasn1.Tag(0).ContextSpecific())
	})
	requireExplicitPolicy1 := b.BytesOrPanic()

	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		seq.AddASN1Int64WithTag(2, cbasn1.Tag(0).ContextSpecific())
	})
	requireExplicitPolicy2 := b.BytesOrPanic()

	// A version of the intermediate that sets requireExplicitPolicy, skipping
	// zero certificates.
	intermediateRequire := intermediate
	intermediateRequire.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: requireExplicitPolicy0}}
	mustGenerateCertificate("policy_intermediate_require.pem", &intermediateRequire, &root)

	// Same as above, but there are no policies on the intermediate.
	intermediateRequire.template.Policies = nil
	mustGenerateCertificate("policy_intermediate_require_no_policies.pem", &intermediateRequire, &root)

	// Same as above, but the policy list has duplicates.
	intermediateRequire.template.Policies = []x509.OID{testOID1, testOID2, testOID2}
	mustGenerateCertificate("policy_intermediate_require_duplicate.pem", &intermediateRequire, &root)

	// Corresponding certificates that instead assert the anyPolicy OID.
	intermediateAny := intermediate
	intermediateAny.template.Policies = []x509.OID{anyPolicyOID}
	mustGenerateCertificate("policy_intermediate_any.pem", &intermediateAny, &root)

	// Other requireExplicitPolicy values, on the leaf and intermediate.
	intermediateRequire = intermediate
	intermediateRequire.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: requireExplicitPolicy1}}
	mustGenerateCertificate("policy_intermediate_require1.pem", &intermediateRequire, &root)
	intermediateRequire.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: requireExplicitPolicy2}}
	mustGenerateCertificate("policy_intermediate_require2.pem", &intermediateRequire, &root)
	leafRequire := leaf
	leafRequire.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: requireExplicitPolicy0}}
	mustGenerateCertificate("policy_leaf_require.pem", &leafRequire, &intermediate)
	leafRequire.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: requireExplicitPolicy1}}
	mustGenerateCertificate("policy_leaf_require1.pem", &leafRequire, &intermediate)

	leafAny := leaf
	leafAny.template.Policies = []x509.OID{anyPolicyOID}
	mustGenerateCertificate("policy_leaf_any.pem", &leafAny, &intermediate)

	// An intermediate which maps OID1 to (OID2, OID3), and which asserts the
	// input OIDs either all at once, or as anyPolicy. Although Go supports
	// this extension, CreateCertificate cannot serialize it. See
	// http://go.dev/issue/82347
	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		// Map OID3 to (OID1, OID2).
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID3)
			addOID(mapping, testOID1)
		})
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID3)
			addOID(mapping, testOID2)
		})

		// Map all pairs of OID4 and OID5 to each other.
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID4)
			addOID(mapping, testOID4)
		})
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID4)
			addOID(mapping, testOID5)
		})
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID5)
			addOID(mapping, testOID4)
		})
		seq.AddASN1(cbasn1.SEQUENCE, func(mapping *cryptobyte.Builder) {
			addOID(mapping, testOID5)
			addOID(mapping, testOID5)
		})
	})
	intermediateMapped := intermediate
	intermediateMapped.template.Policies = []x509.OID{testOID1, testOID2, testOID3, testOID4, testOID5}
	intermediateMapped.template.ExtraExtensions = []pkix.Extension{{Id: policyMappingsOID, Value: b.BytesOrPanic()}}
	mustGenerateCertificate("policy_intermediate_mapped.pem", &intermediateMapped, &root)

	intermediateMapped.template.Policies = []x509.OID{anyPolicyOID}
	mustGenerateCertificate("policy_intermediate_mapped_any.pem", &intermediateMapped, &root)

	intermediateMapped.template.Policies = []x509.OID{testOID3}
	mustGenerateCertificate("policy_intermediate_mapped_oid3.pem", &intermediateMapped, &root)

	// Leaves which assert more specific OIDs, to test intermediate_mapped.
	leafSingle := leaf
	leafSingle.template.Policies = []x509.OID{testOID1}
	mustGenerateCertificate("policy_leaf_oid1.pem", &leafSingle, &intermediate)
	leafSingle.template.Policies = []x509.OID{testOID2}
	mustGenerateCertificate("policy_leaf_oid2.pem", &leafSingle, &intermediate)
	leafSingle.template.Policies = []x509.OID{testOID3}
	mustGenerateCertificate("policy_leaf_oid3.pem", &leafSingle, &intermediate)
	leafSingle.template.Policies = []x509.OID{testOID4}
	mustGenerateCertificate("policy_leaf_oid4.pem", &leafSingle, &intermediate)
	leafSingle.template.Policies = []x509.OID{testOID5}
	mustGenerateCertificate("policy_leaf_oid5.pem", &leafSingle, &intermediate)

	leafNone := leaf
	leafNone.template.Policies = nil
	mustGenerateCertificate("policy_leaf_none.pem", &leafNone, &intermediate)

	// Make version of Root, signed by Root 2, with policy mapping inhibited.
	// This can be combined with intermediateMapped to test the combination.
	// Although Go supports this extension, CreateCertificate cannot
	// serialize it. See http://go.dev/issue/82347
	b = cryptobyte.NewBuilder(nil)
	b.AddASN1(cbasn1.SEQUENCE, func(seq *cryptobyte.Builder) {
		seq.AddASN1Int64WithTag(0, cbasn1.Tag(1).ContextSpecific())
	})
	inhibitPolicyMapping0 := b.BytesOrPanic()

	inhibitMapping := root
	inhibitMapping.template.Policies = []x509.OID{anyPolicyOID}
	inhibitMapping.template.ExtraExtensions = []pkix.Extension{{Id: policyConstraintsOID, Value: inhibitPolicyMapping0}}
	mustGenerateCertificate("policy_root_cross_inhibit_mapping.pem", &inhibitMapping, &root2)
}

const leafKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoPUXNXuH9mgiS/nk
024SYxryxMa3CyGJldiHymLxSquhRANCAASRKti8VW2Rkma+Kt9jQkMNitlCs0l5
w8u3SSwm7HZREvmcBCJBjVIREacRqI0umhzR2V5NLzBBP9yPD/A+Ch5X
-----END PRIVATE KEY-----`

const intermediateKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgWHKCKgY058ahE3t6
vpxVQgzlycgCVMogwjK0y3XMNfWhRANCAATiOnyojN4xS5C8gJ/PHL5cOEsMbsoE
Y6KT9xRQSh8lEL4d1Vb36kqUgkpqedEImo0Og4Owk6VWVVR/m4Lk+yUw
-----END PRIVATE KEY-----`

const rootKeyPEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBwND/eHytW0I417J
Hr+qcPlp5N1jM3ACXys57bPujg+hRANCAAQmdqXYl1GvY7y3jcTTK6MVXIQr44Tq
ChRYI6IeV9tIB6jIsOY+Qol1bk8x/7A5FGOnUWFVLEAPEPSJwPndjolt
-----END PRIVATE KEY-----`

func mustParseECDSAKey(in string) *ecdsa.PrivateKey {
	keyBlock, _ := pem.Decode([]byte(in))
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		panic("could not decode private key")
	}
	key := must(x509.ParsePKCS8PrivateKey(keyBlock.Bytes))
	return key.(*ecdsa.PrivateKey)
}
