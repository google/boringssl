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

package runner

import (
	"crypto"
	"fmt"
	"slices"
)

func hashToString(hash crypto.Hash) string {
	switch hash {
	case crypto.SHA256:
		return "SHA256"
	case crypto.SHA384:
		return "SHA384"
	default:
		panic(fmt.Sprintf("unknown hash %d", hash))
	}
}

func addPSKTests() {
	pskSHA256Credential := Credential{
		Type:         CredentialTypePreSharedKey,
		PreSharedKey: slices.Repeat([]byte{'A', 'B', 'C', 'D'}, 8),
		PSKIdentity:  []byte("psk1"),
		PSKContext:   []byte("context1"),
		PSKHash:      crypto.SHA256,
	}
	pskSHA384Credential := Credential{
		Type:         CredentialTypePreSharedKey,
		PreSharedKey: slices.Repeat([]byte{'E', 'F', 'G', 'H'}, 12),
		PSKIdentity:  []byte("psk2"),
		PSKContext:   []byte("context2"),
		PSKHash:      crypto.SHA384,
	}

	hashToPSK := func(hash crypto.Hash) *Credential {
		switch hash {
		case crypto.SHA256:
			return &pskSHA256Credential
		case crypto.SHA384:
			return &pskSHA384Credential
		default:
			panic(fmt.Sprintf("unknown hash %d", hash))
		}
	}
	hashToCipher := func(hash crypto.Hash) uint16 {
		switch hash {
		case crypto.SHA256:
			return TLS_AES_128_GCM_SHA256
		case crypto.SHA384:
			return TLS_AES_256_GCM_SHA384
		default:
			panic(fmt.Sprintf("unknown hash %d", hash))
		}
	}

	for _, protocol := range []protocol{tls, dtls, quic} {
		// Test that SHA-256 and SHA-384 PSKs can be used with SHA-256 and
		// SHA-384 ciphers.
		for _, pskHash := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
			psk := hashToPSK(pskHash)
			for _, cipherHash := range []crypto.Hash{crypto.SHA256, crypto.SHA384} {
				cipher := hashToCipher(cipherHash)
				testCases = append(testCases, testCase{
					protocol: protocol,
					name:     fmt.Sprintf("PSK-Client-%s-%s-%s", hashToString(pskHash), hashToString(cipherHash), protocol),
					config: Config{
						Credential:   psk,
						MaxVersion:   VersionTLS13,
						CipherSuites: []uint16{cipher},
					},
					shimCredentials: []*Credential{psk},
					// Also test that the resulting session can be reused.
					resumeSession: true,
					// Override the default behavior of expecting a peer certificate on
					// resumption connections.
					flags: []string{"-expect-no-peer-cert"},
				})

				// Test with HelloRetryRequest to ensure the client computes
				// the second ClientHello's binder correctly, and also accounts
				// for the PSK list getting smaller once the cipher is known.
				testCases = append(testCases, testCase{
					protocol: protocol,
					name:     fmt.Sprintf("PSK-Client-HRR-%s-%s-%s", hashToString(pskHash), hashToString(cipherHash), protocol),
					config: Config{
						Credential:   psk,
						MaxVersion:   VersionTLS13,
						CipherSuites: []uint16{cipher},
						Bugs: ProtocolBugs{
							SendHelloRetryRequestCookie: []byte("cookie"),
						},
					},
					shimCredentials: []*Credential{psk},
					// Also test that the resulting session can be reused.
					resumeSession: true,
					// Override the default behavior of expecting a peer certificate on
					// resumption connections.
					flags: []string{"-expect-no-peer-cert"},
				})
			}
		}

		// If the client is configured to offer multiple PSKs, it should accept
		// either from the server.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-AcceptFirst-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
			},
			shimCredentials: []*Credential{&pskSHA256Credential, &pskSHA384Credential},
			flags:           []string{"-expect-selected-credential", "0"},
		})
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-AcceptSecond-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA384Credential,
			},
			shimCredentials: []*Credential{&pskSHA256Credential, &pskSHA384Credential},
			flags:           []string{"-expect-selected-credential", "1"},
		})

		// If the client is configured (on the second connection) with both PSKs and
		// a session, the PSK is still usable.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-DeclineSession-%s", protocol),
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
			},
			resumeConfig: &Config{
				MaxVersion:             VersionTLS13,
				Credential:             &pskSHA256Credential,
				SessionTicketsDisabled: true,
			},
			shimCredentials:      []*Credential{&pskSHA256Credential},
			resumeSession:        true,
			expectResumeRejected: true,
			// The runner will not provision a ticket on the second connection.
			flags: []string{"-on-resume-expect-no-session"},
		})

		// The client should reject out-of-bounds PSK indices.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-OutOfBoundsIndex-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
				Bugs: ProtocolBugs{
					// The shim will import two PSKs from the credential, so
					// only indices 0 and 1 are valid,
					AlwaysSelectPSKIdentity: ptrTo(uint16(2)),
				},
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			shouldFail:      true,
			expectedError:   ":PSK_IDENTITY_NOT_FOUND:",
		})
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-OutOfBoundsIndex-HRR-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
				Bugs: ProtocolBugs{
					SendHelloRetryRequestCookie: []byte("cookie"),
					// The shim will import two PSKs from the credential, but
					// then prune them in the second ClientHello, so only index
					// 0 is valid.
					AlwaysSelectPSKIdentity: ptrTo(uint16(1)),
				},
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			shouldFail:      true,
			expectedError:   ":PSK_IDENTITY_NOT_FOUND:",
		})

		// The client should reject psk_ke connections. We require psk_dhe_ke.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-NoKeyShare-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
				Bugs: ProtocolBugs{
					NegotiatePSKResumption: true,
				},
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			shouldFail:      true,
			expectedError:   ":MISSING_KEY_SHARE:",
		})

		// By default, if the client configures PSKs, it should reject server
		// responses that do use certificates, including TLS 1.2.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-PSKRequired-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &rsaCertificate,
				Bugs: ProtocolBugs{
					// Ignore the client's lack of signature_algorithms.
					IgnorePeerSignatureAlgorithmPreferences: true,
				},
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			shouldFail:      true,
			expectedError:   ":MISSING_EXTENSION:",
			// The shim sends an alert, but alerts immediately after TLS 1.3
			// ServerHello have an encryption mismatch.
		})
		if protocol != quic {
			testCases = append(testCases, testCase{
				protocol: protocol,
				name:     fmt.Sprintf("PSK-Client-PSKRequired-TLS12-%s", protocol),
				testType: clientTest,
				config: Config{
					MaxVersion: VersionTLS12,
					Credential: &rsaCertificate,
					Bugs: ProtocolBugs{
						// Ignore the client's lack of signature_algorithms.
						IgnorePeerSignatureAlgorithmPreferences: true,
					},
				},
				shimCredentials:    []*Credential{&pskSHA256Credential},
				shouldFail:         true,
				expectedError:      ":UNSUPPORTED_PROTOCOL:",
				expectedLocalError: "remote error: protocol version not supported",
			})
		}

		// The client can be configured to accept certificates or PSKs. In this
		// case, even TLS 1.2 certificates are acceptable.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-PSKOrCert-PSK-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			flags:           []string{"-verify-peer"},
		})
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-PSKOrCert-Cert-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &rsaCertificate,
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			flags:           []string{"-verify-peer"},
		})
		if protocol != quic {
			testCases = append(testCases, testCase{
				protocol: protocol,
				name:     fmt.Sprintf("PSK-Client-PSKOrCert-Cert-TLS12-%s", protocol),
				testType: clientTest,
				config: Config{
					MaxVersion: VersionTLS12,
					Credential: &rsaCertificate,
				},
				shimCredentials: []*Credential{&pskSHA256Credential},
				flags:           []string{"-verify-peer"},
			})
		}

		// When a client is configured with PSKs or certificates, it can even send
		// client certificates, configured from the credential list.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-PSKOrCert-CertRequest-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &rsaCertificate,
				ClientAuth: RequireAnyClientCert,
			},
			shimCredentials: []*Credential{&pskSHA256Credential, &rsaCertificate},
			flags:           []string{"-verify-peer"},
		})
		if protocol != quic {
			testCases = append(testCases, testCase{
				protocol: protocol,
				name:     fmt.Sprintf("PSK-Client-PSKOrCert-CertRequest-TLS12-%s", protocol),
				testType: clientTest,
				config: Config{
					MaxVersion: VersionTLS12,
					Credential: &rsaCertificate,
					ClientAuth: RequireAnyClientCert,
				},
				shimCredentials: []*Credential{&pskSHA256Credential, &rsaCertificate},
				flags:           []string{"-verify-peer"},
			})
		}

		// When a client is configured with PSKs or certificates, the server picks certificates,
		// and the server sends CertificateRequests, it must be possible for the client to
		// proceed without sending any client certificate, even if the credential list has a
		// PSK credential.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-PSKOrCert-CertRequest-NoClientCert-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &rsaCertificate,
				ClientAuth: RequestClientCert,
			},
			shimCredentials: []*Credential{&pskSHA256Credential},
			flags:           []string{"-verify-peer"},
		})
		if protocol != quic {
			testCases = append(testCases, testCase{
				protocol: protocol,
				name:     fmt.Sprintf("PSK-Client-PSKOrCert-CertRequest-NoClientCert-TLS12-%s", protocol),
				testType: clientTest,
				config: Config{
					MaxVersion: VersionTLS12,
					Credential: &rsaCertificate,
					ClientAuth: RequestClientCert,
				},
				shimCredentials: []*Credential{&pskSHA256Credential},
				flags:           []string{"-verify-peer"},
			})
		}

		// The client should reject CertificateRequest messages on PSK connections.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-UnexpectedCertificateRequest-%s", protocol),
			testType: clientTest,
			config: Config{
				MaxVersion: VersionTLS13,
				Credential: &pskSHA256Credential,
				ClientAuth: RequireAnyClientCert,
				Bugs: ProtocolBugs{
					AlwaysSendCertificateRequest: true,
				},
			},
			shimCredentials:    []*Credential{&pskSHA256Credential},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})

		// The client should reject Certificate messages on PSK connections.
		testCases = append(testCases, testCase{
			protocol: protocol,
			name:     fmt.Sprintf("PSK-Client-UnexpectedCertificate-%s", protocol),
			config: Config{
				Credential: &pskSHA256Credential,
				MaxVersion: VersionTLS13,
				Bugs: ProtocolBugs{
					AlwaysSendCertificate:    true,
					UseCertificateCredential: &rsaCertificate,
					// Ignore the client's lack of signature_algorithms.
					IgnorePeerSignatureAlgorithmPreferences: true,
				},
			},
			shimCredentials:    []*Credential{&pskSHA256Credential},
			shouldFail:         true,
			expectedError:      ":UNEXPECTED_MESSAGE:",
			expectedLocalError: "remote error: unexpected message",
		})
	}
}
