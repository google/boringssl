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
)

var (
	certTypesListRPKOnly  = []CertificateType{certTypeRawPublicKey}
	certTypesListRPKX509  = []CertificateType{certTypeRawPublicKey, certTypeX509}
	certTypesListX509RPK  = []CertificateType{certTypeX509, certTypeRawPublicKey}
	certTypesListX509Only = []CertificateType{certTypeX509}
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

func addRawPublicKeyTests() {
	addServerCertTypeTests()
}
