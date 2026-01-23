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
	"fmt"
	"strconv"
)

const certTypeBogus CertificateType = 5

var (
	certTypesListRPKOnly     = []CertificateType{certTypeRawPublicKey}
	certTypesListRPKX509     = []CertificateType{certTypeRawPublicKey, certTypeX509}
	certTypesListX509RPK     = []CertificateType{certTypeX509, certTypeRawPublicKey}
	certTypesListX509Only    = []CertificateType{certTypeX509}
	certTypesListUnknown     = []CertificateType{certTypeBogus}
	certTypesListUnknownX509 = []CertificateType{certTypeX509, certTypeBogus}
	certTypesListRPKUnknown  = []CertificateType{certTypeRawPublicKey, certTypeBogus}
)

func addServerCertTypeTests() {
	// Tests sending list of accepted server cert types in the ClientHello.
	// TODO(crbug.com/467663225): Test server response and rest of the handshake.
	for _, ver := range allVersions(tls) {
		for _, test := range []struct {
			name                         string
			serverCertTypesAccepted      []CertificateType
			expectedClientHelloExtension []CertificateType
		}{
			{
				name:                         "RPKOnly",
				serverCertTypesAccepted:      certTypesListRPKOnly,
				expectedClientHelloExtension: certTypesListRPKOnly,
			},
			{
				name:                         "RPKX509",
				serverCertTypesAccepted:      certTypesListRPKX509,
				expectedClientHelloExtension: certTypesListRPKX509,
			},
			{
				name:                         "X509RPK",
				serverCertTypesAccepted:      certTypesListX509RPK,
				expectedClientHelloExtension: certTypesListX509RPK,
			},
			{
				// Configuring the default cert type only omits the extension.
				name:                         "DefaultOnly-Omitted",
				serverCertTypesAccepted:      certTypesListX509Only,
				expectedClientHelloExtension: []CertificateType{},
			},
		} {
			testCases = append(testCases, testCase{
				testType: clientTest,
				name:     fmt.Sprintf("ServerCertificateType-Client-Requests%s-%s", test.name, ver.name),
				config: Config{
					MinVersion: ver.version,
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						ExpectServerCertificateTypes: test.expectedClientHelloExtension,
					},
				},
				flags: flagCertTypes("-accepted-peer-cert-types", test.serverCertTypesAccepted),
			})
		}
	}
}

func addClientCertTypeTests() {
	// Tests receiving a client_certificate_type extension from the client and
	// selecting and sending our most-preferred shared cert type.
	for _, ver := range allVersions(tls) {
		for _, test := range []struct {
			name                         string
			clientCertTypesReceived      []CertificateType
			clientCertTypesAccepted      []CertificateType
			expectedServerHelloExtension []CertificateType
			expectedNegotiated           CertificateType
			expectedError                string
			expectedLocalError           string
		}{
			{
				name:                         "RPKReceived-RPKAccepted",
				clientCertTypesReceived:      certTypesListRPKOnly,
				clientCertTypesAccepted:      certTypesListRPKOnly,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				name:                         "RPKX509Received-RPKAccepted",
				clientCertTypesReceived:      certTypesListRPKX509,
				clientCertTypesAccepted:      certTypesListRPKOnly,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				name:                         "X509RPKReceived-RPKAccepted",
				clientCertTypesReceived:      certTypesListX509RPK,
				clientCertTypesAccepted:      certTypesListRPKOnly,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				name:                         "RPKX509Received-RPKX509Accepted",
				clientCertTypesReceived:      certTypesListRPKX509,
				clientCertTypesAccepted:      certTypesListRPKX509,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				name:                         "X509RPKReceived-RPKX509Accepted",
				clientCertTypesReceived:      certTypesListX509RPK,
				clientCertTypesAccepted:      certTypesListRPKX509,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				name:                         "RPKX509Received-X509RPKAccepted",
				clientCertTypesReceived:      certTypesListRPKX509,
				clientCertTypesAccepted:      certTypesListX509RPK,
				expectedServerHelloExtension: certTypesListX509Only,
				expectedNegotiated:           certTypeX509,
			},
			{
				name:                         "X509RPKReceived-X509RPKAccepted",
				clientCertTypesReceived:      certTypesListX509RPK,
				clientCertTypesAccepted:      certTypesListX509RPK,
				expectedServerHelloExtension: certTypesListX509Only,
				expectedNegotiated:           certTypeX509,
			},
			{
				name:                    "RejectsInvalidEmptyExtension",
				clientCertTypesReceived: []CertificateType{},
				clientCertTypesAccepted: certTypesListX509RPK,
				expectedError:           ":DECODE_ERROR:",
				expectedLocalError:      "remote error: illegal parameter",
			},
			{
				// The client should have omitted the extension if only the default is
				// accepted.
				name:                    "RejectsInvalidDefaultOnly",
				clientCertTypesReceived: certTypesListX509Only,
				clientCertTypesAccepted: certTypesListX509RPK,
				expectedError:           ":DECODE_ERROR:",
				expectedLocalError:      "remote error: illegal parameter",
			},
			{
				// The client's list contains only an unknown value, which is ignored.
				// Negotiating a client cert type value fails.
				name:                    "IgnoresUnknownValue-NoOtherType",
				clientCertTypesReceived: certTypesListUnknown,
				clientCertTypesAccepted: certTypesListX509RPK,
				expectedError:           ":UNSUPPORTED_CERTIFICATE:",
				expectedLocalError:      "remote error: unsupported certificate",
			},
			{
				// The client's list contains an unknown value, which is ignored, and
				// a recognized value, which is not shared with the server.
				name:                    "IgnoresUnknownValue-NoSharedType",
				clientCertTypesReceived: certTypesListUnknownX509,
				clientCertTypesAccepted: certTypesListRPKOnly,
				expectedError:           ":UNSUPPORTED_CERTIFICATE:",
				expectedLocalError:      "remote error: unsupported certificate",
			},
			{
				// The client's list contains an unknown value, which is ignored, and
				// a recognized value, which is accepted successfully.
				name:                         "IgnoresUnknownValue-RPKAccepted",
				clientCertTypesReceived:      certTypesListRPKUnknown,
				clientCertTypesAccepted:      certTypesListX509RPK,
				expectedServerHelloExtension: certTypesListRPKOnly,
				expectedNegotiated:           certTypeRawPublicKey,
			},
			{
				// If the client does not send the extension, the server should treat it
				// as X.509 only by default.
				name:                         "NoClientHelloCertTypes-SelectsX509ByDefault",
				clientCertTypesReceived:      nil,
				clientCertTypesAccepted:      certTypesListRPKX509,
				expectedServerHelloExtension: []CertificateType{},
				expectedNegotiated:           certTypeX509,
			},
			{
				// If the client does not send the extension, but the server is
				// configured to only accept RPKs, the connection should fail.
				name:                    "NoClientHelloCertTypes-NoSharedType",
				clientCertTypesReceived: nil,
				clientCertTypesAccepted: certTypesListRPKOnly,
				expectedError:           ":UNSUPPORTED_CERTIFICATE:",
				expectedLocalError:      "remote error: unsupported certificate",
			},
		} {
			flags :=
				append(flagCertTypes("-accepted-peer-cert-types", test.clientCertTypesAccepted),
					"-require-any-client-certificate")
			// The handshake currently fails because the rest of the RPK client cert
			// flow isn't yet implemented.
			// TODO(crbug.com/467663225): Test client response and rest of the handshake.
			shouldFail := true
			expectedError := ":PEER_DID_NOT_RETURN_A_CERTIFICATE:"
			expectedLocalError := "remote error: handshake failure"
			if ver.version == VersionTLS13 {
				expectedLocalError = "remote error: certificate required"
			}
			if test.expectedError != "" {
				shouldFail = true
				expectedError = test.expectedError
				expectedLocalError = test.expectedLocalError
			} else {
				flags = append(flags,
					"-expect-client-certificate-type", strconv.Itoa(int(test.expectedNegotiated)))
			}
			testCases = append(testCases, testCase{
				testType: serverTest,
				name:     fmt.Sprintf("ClientCertificateType-Server-%s-%s", test.name, ver.name),
				config: Config{
					MinVersion: ver.version,
					MaxVersion: ver.version,
					Bugs: ProtocolBugs{
						SendClientCertificateTypes:   test.clientCertTypesReceived,
						ExpectClientCertificateTypes: test.expectedServerHelloExtension,
					},
				},
				flags:              flags,
				shouldFail:         shouldFail,
				expectedError:      expectedError,
				expectedLocalError: expectedLocalError,
			})
		}
	}
}

func addRawPublicKeyTests() {
	addServerCertTypeTests()
	addClientCertTypeTests()
}
