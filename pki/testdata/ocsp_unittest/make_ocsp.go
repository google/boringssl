// Copyright 2026 The BoringSSL Authors
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

// This script is called without any arguments to re-generate all of the *.pem
// files in the script's directory.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	nextSerial int64 = 1

	certDate     = time.Date(2017, 1, 1, 0, 0, 0, 0, time.UTC)
	certExpire   = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC)
	revokeDate   = time.Date(2017, 2, 1, 0, 0, 0, 0, time.UTC)
	thisDate     = time.Date(2017, 3, 1, 0, 0, 0, 0, time.UTC)
	producedDate = time.Date(2017, 3, 2, 0, 0, 0, 0, time.UTC)
	verifyDate   = time.Date(2017, 3, 5, 0, 0, 0, 0, time.UTC)
	nextDate     = time.Date(2017, 6, 1, 0, 0, 0, 0, time.UTC)

	oidSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA1WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidBasicOCSPResponse = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}
	oidCommonName        = asn1.ObjectIdentifier{2, 5, 4, 3}
)

type certInfo struct {
	der         []byte
	cert        *x509.Certificate
	key         *rsa.PrivateKey
	issuer      *certInfo
	serialBytes []byte
}

func makeNameDER(commonName string) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidCommonName)
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) {
					b.AddBytes([]byte(commonName))
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func loadKey(path string) *rsa.PrivateKey {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		panic("failed to decode PEM key: " + path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key.(*rsa.PrivateKey)
}

func createCert(name, keyPath string, signer *certInfo, ocsp bool) *certInfo {
	privKey := loadKey(keyPath)
	subjectDER := makeNameDER(name)

	serial := nextSerial
	nextSerial++

	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(serial),
		RawSubject:         subjectDER,
		NotBefore:          certDate,
		NotAfter:           certExpire,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	if ocsp {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}
	}

	var issuerTmpl *x509.Certificate
	var issuerKey *rsa.PrivateKey
	if signer != nil {
		issuerTmpl = signer.cert
		issuerKey = signer.key
	} else {
		issuerTmpl = tmpl
		issuerKey = privKey
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, issuerTmpl, &privKey.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}
	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		panic(err)
	}

	info := &certInfo{
		der:         derBytes,
		cert:        parsedCert,
		key:         privKey,
		serialBytes: []byte{byte(serial)},
	}
	if signer != nil {
		info.issuer = signer
	} else {
		info.issuer = info
	}
	return info
}

// createCertWithRawSerial creates a copy of baseCert with its serialNumber INTEGER
// replaced by rawSerialBytes, and re-signs the certificate with its issuer's key.
func createCertWithRawSerial(baseCert *certInfo, rawSerialBytes []byte) *certInfo {
	s := cryptobyte.String(baseCert.der)
	var certSeq, tbsSeq cryptobyte.String
	if !s.ReadASN1(&certSeq, cbasn1.SEQUENCE) ||
		!certSeq.ReadASN1(&tbsSeq, cbasn1.SEQUENCE) {
		panic("failed to parse Certificate DER")
	}

	// Read version [0] EXPLICIT TLV raw bytes
	var versionTLV cryptobyte.String
	if !tbsSeq.ReadASN1Element(&versionTLV, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		panic("failed to read version from tbsCertificate")
	}
	// Skip original serialNumber INTEGER
	var oldSerial cryptobyte.String
	if !tbsSeq.ReadASN1(&oldSerial, cbasn1.INTEGER) {
		panic("failed to read serialNumber from tbsCertificate")
	}
	restOfTBS := []byte(tbsSeq)

	var newTBSBuilder cryptobyte.Builder
	newTBSBuilder.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(versionTLV)
		b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
			b.AddBytes(rawSerialBytes)
		})
		b.AddBytes(restOfTBS)
	})
	newTBS := newTBSBuilder.BytesOrPanic()

	digest := sha256.Sum256(newTBS)
	sig, err := rsa.SignPKCS1v15(nil, baseCert.issuer.key, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}

	var newCertBuilder cryptobyte.Builder
	newCertBuilder.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(newTBS)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oidSHA256WithRSA)
			b.AddASN1NULL()
		})
		b.AddASN1BitString(sig)
	})
	newDER := newCertBuilder.BytesOrPanic()

	return &certInfo{
		der:         newDER,
		cert:        baseCert.cert,
		key:         baseCert.key,
		issuer:      baseCert.issuer,
		serialBytes: rawSerialBytes,
	}
}

func extractSPKBitStringBytes(spkiDER []byte) []byte {
	s := cryptobyte.String(spkiDER)
	var seq, alg cryptobyte.String
	var spk asn1.BitString
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) ||
		!seq.ReadASN1(&alg, cbasn1.SEQUENCE) ||
		!seq.ReadASN1BitString(&spk) {
		panic("failed to parse SubjectPublicKeyInfo")
	}
	return spk.Bytes
}

type responderID struct {
	byName []byte
	byKey  []byte
}

func getNameResponderID(c *certInfo) responderID {
	return responderID{byName: c.cert.RawSubject}
}

func getKeyHashResponderID(c *certInfo) responderID {
	spkBytes := extractSPKBitStringBytes(c.cert.RawSubjectPublicKeyInfo)
	keyHash := sha1.Sum(spkBytes)
	return responderID{byKey: keyHash[:]}
}

func addExtensions(b *cryptobyte.Builder, tag uint8, exts []pkix.Extension) {
	if len(exts) == 0 {
		return
	}
	b.AddASN1(cbasn1.Tag(tag).ContextSpecific().Constructed(), func(child *cryptobyte.Builder) {
		child.AddASN1(cbasn1.SEQUENCE, func(extsB *cryptobyte.Builder) {
			for _, ext := range exts {
				extsB.AddASN1(cbasn1.SEQUENCE, func(extB *cryptobyte.Builder) {
					extB.AddASN1ObjectIdentifier(ext.Id)
					if ext.Critical {
						extB.AddASN1(cbasn1.BOOLEAN, func(crit *cryptobyte.Builder) {
							crit.AddUint8(0xff)
						})
					}
					extB.AddASN1(cbasn1.OCTET_STRING, func(value *cryptobyte.Builder) {
						value.AddBytes(ext.Value)
					})
				})
			}
		})
	})
}

type certStatus int

const (
	statusGood    certStatus = 0
	statusRevoked certStatus = 1
	statusUnknown certStatus = 2
)

type singleResponse struct {
	cert       *certInfo
	status     certStatus
	reason     *int
	thisUpdate time.Time
	nextUpdate *time.Time
	revokeTime *time.Time
	extensions []pkix.Extension
}

func marshalSingleResponse(b *cryptobyte.Builder, resp singleResponse) {
	issuer := resp.cert.issuer
	nameHash := sha1.Sum(issuer.cert.RawSubject)
	keyHash := sha1.Sum(extractSPKBitStringBytes(issuer.cert.RawSubjectPublicKeyInfo))

	b.AddASN1(cbasn1.SEQUENCE, func(respB *cryptobyte.Builder) {
		respB.AddASN1(cbasn1.SEQUENCE, func(certID *cryptobyte.Builder) {
			certID.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidSHA1)
			})
			certID.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
				b.AddBytes(nameHash[:])
			})
			certID.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
				b.AddBytes(keyHash[:])
			})
			certID.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
				b.AddBytes(resp.cert.serialBytes)
			})
		})

		switch resp.status {
		case statusGood:
			respB.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {})
		case statusRevoked:
			revTime := revokeDate
			if resp.revokeTime != nil {
				revTime = *resp.revokeTime
			}
			respB.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(revInfo *cryptobyte.Builder) {
				revInfo.AddASN1GeneralizedTime(revTime)
				if resp.reason != nil {
					revInfo.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(child *cryptobyte.Builder) {
						child.AddASN1Enum(int64(*resp.reason))
					})
				}
			})
		case statusUnknown:
			respB.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) {})
		}

		thisUpdate := resp.thisUpdate
		if thisUpdate.IsZero() {
			thisUpdate = thisDate
		}
		respB.AddASN1GeneralizedTime(thisUpdate)

		// nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
		if resp.nextUpdate != nil {
			respB.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1GeneralizedTime(*resp.nextUpdate)
			})
		}

		// singleExtensions [1] EXPLICIT Extensions OPTIONAL
		addExtensions(respB, 1, resp.extensions)
	})
}

const (
	responseStatusSuccessful       = 0
	responseStatusMalformedRequest = 1
	responseStatusInternalError    = 2
	responseStatusTryLater         = 3
	// 4 is not allocated.
	responseStatusSigRequired  = 5
	responseStatusUnauthorized = 6
)

type ocspResponse struct {
	signer         *certInfo
	responseStatus int
	// responseType, if set, overrides the responseType from id-pkix-ocsp-basic
	responseType asn1.ObjectIdentifier
	// version, if set, explicitly encodes a version number.
	version     *int
	responderID responderID
	producedAt  time.Time
	responses   []singleResponse
	extensions  []pkix.Extension
	sigAlg      x509.SignatureAlgorithm
	// signature, if set, overrides the signature.
	signature []byte
	certs     []*certInfo
	// invalidResponseData, if true, causes the tbsResponseData to be invalid.
	invalidResponseData bool
}

func marshalBasicOCSPResponse(b *cryptobyte.Builder, resp *ocspResponse) {
	sigAlg := resp.sigAlg
	if sigAlg == 0 {
		sigAlg = x509.SHA1WithRSA
	}

	var sigAlgOID asn1.ObjectIdentifier
	var hashFunc crypto.Hash
	switch sigAlg {
	case x509.SHA1WithRSA:
		sigAlgOID = oidSHA1WithRSA
		hashFunc = crypto.SHA1
	case x509.SHA256WithRSA:
		sigAlgOID = oidSHA256WithRSA
		hashFunc = crypto.SHA256
	default:
		panic(fmt.Sprintf("unrecognized signature algorithm: %s", sigAlg))
	}

	var tbsBuilder cryptobyte.Builder
	if resp.invalidResponseData {
		tbsBuilder.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte("invalid"))
		})
	} else {
		tbsBuilder.AddASN1(cbasn1.SEQUENCE, func(respData *cryptobyte.Builder) {
			if resp.version != nil && *resp.version != 1 {
				respData.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1Int64(int64(*resp.version))
				})
			}
			responderID := resp.responderID
			if responderID.byKey != nil {
				respData.AddASN1(cbasn1.Tag(2).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.OCTET_STRING, func(b *cryptobyte.Builder) {
						b.AddBytes(responderID.byKey)
					})
				})
			} else {
				respData.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					if responderID.byName != nil {
						b.AddBytes(responderID.byName)
					} else {
						// Default to the signer.
						b.AddBytes(resp.signer.cert.RawSubject)
					}
				})
			}

			producedAt := resp.producedAt
			if producedAt.IsZero() {
				producedAt = producedDate
			}
			respData.AddASN1GeneralizedTime(producedAt)

			respData.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, r := range resp.responses {
					marshalSingleResponse(b, r)
				}
			})

			addExtensions(respData, 1, resp.extensions)
		})
	}
	tbsBytes := tbsBuilder.BytesOrPanic()

	b.AddASN1(cbasn1.SEQUENCE, func(basicResp *cryptobyte.Builder) {
		basicResp.AddBytes(tbsBytes)
		basicResp.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sigAlgOID)
			// TODO(davidben): This should have an ASN.1 NULL.
		})

		signature := resp.signature
		if signature == nil {
			h := hashFunc.New()
			h.Write(tbsBytes)
			var err error
			signature, err = rsa.SignPKCS1v15(nil, resp.signer.key, hashFunc, h.Sum(nil))
			if err != nil {
				panic(err)
			}
		}
		basicResp.AddASN1BitString(signature)
		if len(resp.certs) > 0 {
			basicResp.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(certsWrapper *cryptobyte.Builder) {
				certsWrapper.AddASN1(cbasn1.SEQUENCE, func(certs *cryptobyte.Builder) {
					for _, c := range resp.certs {
						certs.AddBytes(c.der)
					}
				})
			})
		}
	})
}

func createOCSPResponse(resp *ocspResponse) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(respB *cryptobyte.Builder) {
		respB.AddASN1Enum(int64(resp.responseStatus))
		if resp.responseStatus != responseStatusSuccessful {
			return
		}
		respB.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(child *cryptobyte.Builder) {
			child.AddASN1(cbasn1.SEQUENCE, func(respBytes *cryptobyte.Builder) {
				responseType := resp.responseType
				if len(responseType) == 0 {
					responseType = oidBasicOCSPResponse
				}
				respBytes.AddASN1ObjectIdentifier(responseType)
				respBytes.AddASN1(cbasn1.OCTET_STRING, func(respWrapper *cryptobyte.Builder) {
					marshalBasicOCSPResponse(respWrapper, resp)
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func createOCSPRequest(issuer, cert *certInfo) []byte {
	nameHash := sha1.Sum(issuer.cert.RawSubject)
	keyHash := sha1.Sum(extractSPKBitStringBytes(issuer.cert.RawSubjectPublicKeyInfo))

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(ocspReq *cryptobyte.Builder) {
		ocspReq.AddASN1(cbasn1.SEQUENCE, func(tbsReq *cryptobyte.Builder) {
			tbsReq.AddASN1(cbasn1.SEQUENCE, func(reqList *cryptobyte.Builder) {
				reqList.AddASN1(cbasn1.SEQUENCE, func(req *cryptobyte.Builder) {
					req.AddASN1(cbasn1.SEQUENCE, func(reqCert *cryptobyte.Builder) {
						reqCert.AddASN1(cbasn1.SEQUENCE, func(hashAlg *cryptobyte.Builder) {
							hashAlg.AddASN1ObjectIdentifier(oidSHA1)
							hashAlg.AddASN1NULL()
						})
						reqCert.AddASN1(cbasn1.OCTET_STRING, func(child *cryptobyte.Builder) {
							child.AddBytes(nameHash[:])
						})
						reqCert.AddASN1(cbasn1.OCTET_STRING, func(child *cryptobyte.Builder) {
							child.AddBytes(keyHash[:])
						})
						reqCert.AddASN1(cbasn1.INTEGER, func(child *cryptobyte.Builder) {
							child.AddBytes(cert.serialBytes)
						})
					})
				})
			})
		})
	})
	return b.BytesOrPanic()
}

func store(filename, description string, ca, cert *certInfo, dataDER []byte) {
	ocspRequestDER := createOCSPRequest(ca, cert)

	var buf bytes.Buffer
	buf.WriteString(description)
	buf.WriteString("\n")
	if err := pem.Encode(&buf, &pem.Block{Type: "OCSP RESPONSE", Bytes: dataDER}); err != nil {
		panic(err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CA CERTIFICATE", Bytes: ca.der}); err != nil {
		panic(err)
	}
	buf.WriteString("\n")
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.der}); err != nil {
		panic(err)
	}
	buf.WriteString("\n")
	if err := pem.Encode(&buf, &pem.Block{Type: "OCSP REQUEST", Bytes: ocspRequestDER}); err != nil {
		panic(err)
	}

	if err := os.WriteFile(filename+".pem", buf.Bytes(), 0644); err != nil {
		panic(err)
	}
}

func main() {
	rootCA := createCert("Test CA", "root.key", nil, false)
	ca := createCert("Test Intermediate CA", "intermediate.key", rootCA, false)
	caLink := createCert("Test OCSP Signer", "ocsp_signer.key", ca, true)
	caBadLink := createCert("Test False OCSP Signer", "bad_ocsp_signer.key", ca, false)
	cert := createCert("Test Cert", "cert.key", ca, false)
	junkCert := createCert("Random Cert", "cert2.key", nil, false)

	create := func(resp ocspResponse) []byte {
		if resp.signer == nil {
			resp.signer = ca
		}
		if resp.responses == nil {
			resp.responses = []singleResponse{{
				cert:   cert,
				status: statusGood,
			}}
		}
		return createOCSPResponse(&resp)
	}

	store(
		"no_response",
		"No SingleResponses attached to the response",
		ca, cert,
		create(ocspResponse{responses: []singleResponse{}}),
	)

	store(
		"malformed_request",
		"Has a status of MALFORMED_REQUEST",
		ca, cert,
		create(ocspResponse{responseStatus: responseStatusMalformedRequest}),
	)

	store(
		"bad_status",
		"Has an invalid status larger than the defined Status enumeration",
		ca, cert,
		create(ocspResponse{responseStatus: 17}),
	)

	store(
		"bad_ocsp_type",
		"Has an invalid OCSP OID",
		ca, cert,
		create(ocspResponse{responseType: asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}}),
	)

	store(
		"bad_signature",
		"Has an invalid signature",
		ca, cert,
		create(ocspResponse{signature: []byte{0xde, 0xad, 0xbe, 0xef}}),
	)

	store(
		"ocsp_sign_direct",
		"Signed directly by the issuer",
		ca, cert,
		create(ocspResponse{signer: ca, certs: []*certInfo{}}),
	)

	store(
		"ocsp_sign_indirect",
		"Signed indirectly through an intermediate",
		ca, cert,
		create(ocspResponse{signer: caLink, certs: []*certInfo{caLink}}),
	)

	store(
		"ocsp_sign_indirect_missing",
		"Signed indirectly through a missing intermediate",
		ca, cert,
		create(ocspResponse{signer: caLink, certs: []*certInfo{}}),
	)

	store(
		"ocsp_sign_bad_indirect",
		"Signed through an intermediate without the correct key usage",
		ca, cert,
		create(ocspResponse{signer: caBadLink, certs: []*certInfo{caBadLink}}),
	)

	store(
		"ocsp_extra_certs",
		"Includes extra certs",
		ca, cert,
		create(ocspResponse{signer: ca, certs: []*certInfo{ca, caLink}}),
	)

	store(
		"has_version",
		"Includes a default version V1",
		ca, cert,
		// TODO(davidben): This test actually does not include it.
		create(ocspResponse{version: new(1)}),
	)

	store(
		"responder_name",
		"Uses byName to identify the signer",
		ca, cert,
		create(ocspResponse{responderID: getNameResponderID(ca)}),
	)

	store(
		"responder_id",
		"Uses byKey to identify the signer",
		ca, cert,
		create(ocspResponse{responderID: getKeyHashResponderID(ca)}),
	)

	store(
		"has_extension",
		"Includes an x509v3 extension",
		ca, cert,
		create(ocspResponse{
			extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("DEADBEEF")},
			},
		}),
	)

	store(
		"good_response",
		"Is a valid response for the cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
			},
		}),
	)

	store(
		"good_response_sha256",
		"Is a valid response for the cert with a SHA256 signature",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
			},
			sigAlg: x509.SHA256WithRSA,
		}),
	)

	store(
		"good_response_next_update",
		"Is a valid response for the cert until nextUpdate",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:       cert,
					status:     statusGood,
					nextUpdate: new(nextDate),
				},
			},
		}),
	)

	store(
		"revoke_response",
		"Is a REVOKE response for the cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusRevoked},
			},
		}),
	)

	store(
		"revoke_response_reason",
		"Is a REVOKE response for the cert with a reason",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:       cert,
					status:     statusRevoked,
					revokeTime: new(revokeDate),
					reason:     new(1), // keyCompromise
				},
			},
		}),
	)

	store(
		"unknown_response",
		"Is an UNKNOWN response for the cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusUnknown},
			},
		}),
	)

	store(
		"multiple_response",
		"Has multiple responses for the cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
				{cert: cert, status: statusUnknown},
			},
		}),
	)

	store(
		"other_response",
		"Is a response for a different cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: junkCert, status: statusGood},
				{cert: junkCert, status: statusRevoked},
			},
		}),
	)

	store(
		"has_single_extension",
		"Has an extension in the SingleResponse",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:   cert,
					status: statusGood,
					extensions: []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte("DEADBEEF")},
					},
				},
			},
		}),
	)

	store(
		"has_critical_single_extension",
		"Has a critical extension in the SingleResponse",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:   cert,
					status: statusGood,
					extensions: []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte("DEADBEEF")},
					},
				},
			},
		}),
	)

	store(
		"has_critical_response_extension",
		"Has a critical extension in the ResponseData",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
			},
			extensions: []pkix.Extension{
				{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte("DEADBEEF")},
			},
		}),
	)

	store(
		"has_critical_ct_extension",
		"Has a critical CT extension in the SingleResponse",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:   cert,
					status: statusGood,
					extensions: []pkix.Extension{
						{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 5}, Critical: true, Value: []byte("DEADBEEF")},
					},
				},
			},
		}),
	)

	store(
		"missing_response",
		"Missing a response for the cert",
		ca, cert,
		create(ocspResponse{responseStatus: responseStatusSuccessful, responses: []singleResponse{}}),
	)

	store(
		"stale_response",
		"nextUpdate is before the current time",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:       cert,
					status:     statusGood,
					thisUpdate: verifyDate.Add(-2 * 24 * time.Hour),
					nextUpdate: new(verifyDate.Add(-1 * 24 * time.Hour)),
				},
			},
		}),
	)

	store(
		"future_response",
		"thisUpdate is after the current time",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:       cert,
					status:     statusGood,
					thisUpdate: verifyDate.Add(1 * 24 * time.Hour),
				},
			},
		}),
	)

	store(
		"old_response",
		"thisUpdate is over a week before the current time",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{
					cert:       cert,
					status:     statusGood,
					thisUpdate: verifyDate.Add(-8 * 24 * time.Hour),
				},
			},
		}),
	)

	store(
		"produced_early_response",
		"producedAt is before the cert's notBefore",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
			},
			producedAt: certDate.Add(-1 * 24 * time.Hour),
		}),
	)

	store(
		"produced_late_response",
		"producedAt is after the cert's notAfter",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
			},
			producedAt: certExpire.Add(1 * 24 * time.Hour),
		}),
	)

	store(
		"invalid_response",
		"OCSPResponse cannot be parsed",
		ca, cert,
		[]byte("invalid"),
	)

	store(
		"invalid_response_data",
		"ResponseData cannot be parsed",
		ca, cert,
		create(ocspResponse{invalidResponseData: true}),
	)

	store(
		"multiple_response_good_revoked",
		"Has both a good and a revoked response for the cert",
		ca, cert,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: cert, status: statusGood},
				{cert: cert, status: statusRevoked},
			},
		}),
	)

	certInvalidSerial := createCertWithRawSerial(cert, []byte{0x00, 0x05})
	store(
		"good_response_invalid_serial",
		`Is a valid response for the cert, but the cert has an incorrectly encoded
serial number. Until we fix the cert parser (https://crbug.com/533048005), it
is prudent (though not critical) for every acceptable serial number to be
representable in OCSP.`,
		ca, certInvalidSerial,
		create(ocspResponse{
			responses: []singleResponse{
				{cert: certInvalidSerial, status: statusGood},
			},
		}),
	)

	cmd := exec.Command("python3", "annotate_test_data.py")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
