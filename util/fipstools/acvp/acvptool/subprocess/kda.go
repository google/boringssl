// Copyright 2021 The BoringSSL Authors
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

package subprocess

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// The following structures reflect the JSON of ACVP KAS KDF tests. See
// https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-kdf-hkdf.html
// https://pages.nist.gov/ACVP/draft-hammett-acvp-kas-kdf-onestepnocounter.html

type multiModeKda struct {
	modes map[string]primitive
}

func (k multiModeKda) Process(vectorSet []byte, m Transactable) (any, error) {
	var vector struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(vectorSet, &vector); err != nil {
		return nil, fmt.Errorf("invalid KDA test vector: %w", err)
	}
	mode, ok := k.modes[vector.Mode]
	if !ok {
		return nil, fmt.Errorf("unsupported KDA mode %q", vector.Mode)
	}
	return mode.Process(vectorSet, m)
}

type kdaPartyInfo struct {
	IDHex    string `json:"partyId"`
	ExtraHex string `json:"ephemeralData"`
}

func (p *kdaPartyInfo) data() ([]byte, error) {
	ret, err := hex.DecodeString(p.IDHex)
	if err != nil {
		return nil, err
	}
	if len(p.ExtraHex) > 0 {
		extra, err := hex.DecodeString(p.ExtraHex)
		if err != nil {
			return nil, err
		}
		ret = append(ret, extra...)
	}
	return ret, nil
}

type hkdfTestVectorSet struct {
	Mode   string          `json:"mode"`
	Groups []hkdfTestGroup `json:"testGroups"`
}

type hkdfTestGroup struct {
	ID             uint64            `json:"tgId"`
	Type           string            `json:"testType"` // AFT or VAL
	Config         hkdfConfiguration `json:"kdfConfiguration"`
	MultiExpansion bool              `json:"multiExpansion"`
	MultiConfig    hkdfConfiguration `json:"kdfMultiExpansionConfiguration"`
	Tests          []hkdfTest        `json:"tests"`
}

type hkdfTest struct {
	ID            uint64                       `json:"tcId"`
	Params        hkdfParameters               `json:"kdfParameter"`
	PartyU        kdaPartyInfo                 `json:"fixedInfoPartyU"`
	PartyV        kdaPartyInfo                 `json:"fixedInfoPartyV"`
	ExpectedHex   string                       `json:"dkm"`
	MultiParams   hkdfMultiExpansionParameters `json:"kdfMultiExpansionParameter"`
	ExpectedHexes []string                     `json:"dkms"`
}

type hkdfConfiguration struct {
	Type               string `json:"kdfType"`
	OutputBits         uint32 `json:"l"`
	HashName           string `json:"hmacAlg"`
	FixedInfoPattern   string `json:"fixedInfoPattern"`
	FixedInputEncoding string `json:"fixedInfoEncoding"`
}

func (c *hkdfConfiguration) extract() (outBytes uint32, hashName string, err error) {
	if c.Type != "hkdf" ||
		c.FixedInfoPattern != "uPartyInfo||vPartyInfo" ||
		c.FixedInputEncoding != "concatenation" ||
		c.OutputBits%8 != 0 {
		return 0, "", fmt.Errorf("KDA not configured for HKDF: %#v", c)
	}

	return c.OutputBits / 8, c.HashName, nil
}

type hkdfParameters struct {
	SaltHex   string `json:"salt"`
	KeyHex    string `json:"z"`
	AuxKeyHex string `json:"t"`
}

func (p *hkdfParameters) extract() (key, salt []byte, err error) {
	salt, err = hex.DecodeString(p.SaltHex)
	if err != nil {
		return nil, nil, err
	}

	key, err = hex.DecodeString(p.KeyHex)
	if err != nil {
		return nil, nil, err
	}

	// For a hybrid shared secret, the input is Z || T (SP 800-56C Rev. 2).
	auxKey, err := hex.DecodeString(p.AuxKeyHex)
	if err != nil {
		return nil, nil, err
	}
	key = append(key, auxKey...)

	return key, salt, nil
}

type hkdfMultiExpansionParameters struct {
	hkdfParameters
	Iterations []struct {
		OutputBits uint32 `json:"l"`
		InfoHex    string `json:"fixedInfo"`
	} `json:"iterationParameters"`
}

type hkdfTestGroupResponse struct {
	ID    uint64             `json:"tgId"`
	Tests []hkdfTestResponse `json:"tests"`
}

type hkdfTestResponse struct {
	ID      uint64   `json:"tcId"`
	KeyOut  string   `json:"dkm,omitempty"`
	KeysOut []string `json:"dkms,omitempty"`
	Passed  *bool    `json:"testPassed,omitempty"`
}

type hkdf struct{}

func (k *hkdf) Process(vectorSet []byte, m Transactable) (any, error) {
	var parsed hkdfTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	if parsed.Mode != "HKDF" {
		return nil, fmt.Errorf("unexpected KDA mode %q", parsed.Mode)
	}

	var respGroups []hkdfTestGroupResponse
	for _, group := range parsed.Groups {
		group := group
		groupResp := hkdfTestGroupResponse{ID: group.ID}

		var isValidationTest bool
		switch group.Type {
		case "VAL":
			isValidationTest = true
		case "AFT":
			isValidationTest = false
		default:
			return nil, fmt.Errorf("unknown test type %q", group.Type)
		}

		if group.MultiExpansion {
			if group.MultiConfig.Type != "hkdf" {
				return nil, fmt.Errorf("KDA not configured for HKDF: %#v", group.MultiConfig)
			}
			for _, test := range group.Tests {
				response, err := test.processMultiExpansion(group.MultiConfig.HashName, isValidationTest, m)
				if err != nil {
					return nil, err
				}
				groupResp.Tests = append(groupResp.Tests, response)
			}
			m.Barrier(func() {
				respGroups = append(respGroups, groupResp)
			})
			continue
		}

		outBytes, hashName, err := group.Config.extract()
		if err != nil {
			return nil, err
		}

		for _, test := range group.Tests {
			test := test
			testResp := hkdfTestResponse{ID: test.ID}

			key, salt, err := test.Params.extract()
			if err != nil {
				return nil, err
			}
			uData, err := test.PartyU.data()
			if err != nil {
				return nil, err
			}
			vData, err := test.PartyV.data()
			if err != nil {
				return nil, err
			}

			var expected []byte
			if isValidationTest {
				expected, err = hex.DecodeString(test.ExpectedHex)
				if err != nil {
					return nil, err
				}
			}

			info := make([]byte, 0, len(uData)+len(vData))
			info = append(info, uData...)
			info = append(info, vData...)

			m.TransactAsync("HKDF/"+hashName, 1, [][]byte{key, salt, info, uint32le(outBytes)}, func(result [][]byte) error {
				if len(result[0]) != int(outBytes) {
					return fmt.Errorf("HKDF operation resulted in %d bytes but wanted %d", len(result[0]), outBytes)
				}
				if isValidationTest {
					passed := bytes.Equal(expected, result[0])
					testResp.Passed = &passed
				} else {
					testResp.KeyOut = hex.EncodeToString(result[0])
				}

				groupResp.Tests = append(groupResp.Tests, testResp)
				return nil
			})
		}

		m.Barrier(func() {
			respGroups = append(respGroups, groupResp)
		})
	}

	if err := m.Flush(); err != nil {
		return nil, err
	}

	return respGroups, nil
}

func (t *hkdfTest) processMultiExpansion(hashName string, isValidationTest bool, m Transactable) (hkdfTestResponse, error) {
	response := hkdfTestResponse{ID: t.ID}
	if len(t.MultiParams.Iterations) == 0 {
		return response, fmt.Errorf("HKDF multi-expansion test %d has no iterations", t.ID)
	}
	if isValidationTest && len(t.ExpectedHexes) != len(t.MultiParams.Iterations) {
		return response, fmt.Errorf("HKDF multi-expansion test %d has %d expected keys for %d iterations", t.ID, len(t.ExpectedHexes), len(t.MultiParams.Iterations))
	}
	key, salt, err := t.MultiParams.extract()
	if err != nil {
		return response, err
	}
	// Extract once and reuse the resulting key for each expansion.
	prk, err := m.Transact("HKDFExtract/"+hashName, 1, key, salt)
	if err != nil {
		return response, err
	}
	passed := true
	for i, iteration := range t.MultiParams.Iterations {
		if iteration.OutputBits%8 != 0 {
			return response, fmt.Errorf("HKDF output length %d is not a multiple of 8", iteration.OutputBits)
		}
		info, err := hex.DecodeString(iteration.InfoHex)
		if err != nil {
			return response, err
		}
		outBytes := iteration.OutputBits / 8
		result, err := m.Transact("HKDFExpand/"+hashName, 1, prk[0], info, uint32le(outBytes))
		if err != nil {
			return response, err
		}
		if len(result[0]) != int(outBytes) {
			return response, fmt.Errorf("HKDF operation resulted in %d bytes but wanted %d", len(result[0]), outBytes)
		}
		if isValidationTest {
			expected, err := hex.DecodeString(t.ExpectedHexes[i])
			if err != nil {
				return response, err
			}
			if !bytes.Equal(expected, result[0]) {
				passed = false
			}
		} else {
			response.KeysOut = append(response.KeysOut, hex.EncodeToString(result[0]))
		}
	}
	if isValidationTest {
		response.Passed = &passed
	}
	return response, nil
}

type oneStepTestVectorSet struct {
	Mode   string             `json:"mode"`
	Groups []oneStepTestGroup `json:"testGroups"`
}

type oneStepTestGroup struct {
	ID     uint64               `json:"tgId"`
	Type   string               `json:"testType"` // AFT or VAL
	Config oneStepConfiguration `json:"kdfConfiguration"`
	Tests  []oneStepTest        `json:"tests"`
}

type oneStepConfiguration struct {
	Type               string `json:"kdfType"`
	SaltMethod         string `json:"saltMethod"`
	FixedInfoPattern   string `json:"fixedInfoPattern"`
	FixedInputEncoding string `json:"fixedInfoEncoding"`
	AuxFunction        string `json:"auxFunction"`
	OutputBits         uint32 `json:"l"`
}

func (c *oneStepConfiguration) extract() (outBytes uint32, auxFunction string, err error) {
	if c.Type != "oneStepNoCounter" ||
		c.FixedInfoPattern != "uPartyInfo||vPartyInfo" ||
		c.FixedInputEncoding != "concatenation" ||
		c.OutputBits%8 != 0 {
		return 0, "", fmt.Errorf("KDA not configured for OneStepNoCounter: %#v", c)
	}
	return c.OutputBits / 8, c.AuxFunction, nil
}

type oneStepTest struct {
	ID              uint64                `json:"tcId"`
	Params          oneStepTestParameters `json:"kdfParameter"`
	FixedInfoPartyU kdaPartyInfo          `json:"fixedInfoPartyU"`
	FixedInfoPartyV kdaPartyInfo          `json:"fixedInfoPartyV"`
	DerivedKeyHex   string                `json:"dkm,omitempty"` // For VAL tests only.
}

type oneStepTestParameters struct {
	KdfType    string `json:"kdfType"`
	SaltHex    string `json:"salt"`
	ZHex       string `json:"z"`
	OutputBits uint32 `json:"l"`
}

func (p oneStepTestParameters) extract() (key []byte, salt []byte, outLen uint32, err error) {
	if p.KdfType != "oneStepNoCounter" ||
		p.OutputBits%8 != 0 {
		return nil, nil, 0, fmt.Errorf("KDA not configured for OneStepNoCounter: %#v", p)
	}
	outLen = p.OutputBits / 8
	salt, err = hex.DecodeString(p.SaltHex)
	if err != nil {
		return
	}
	key, err = hex.DecodeString(p.ZHex)
	if err != nil {
		return
	}
	return
}

type oneStepTestGroupResponse struct {
	ID    uint64                `json:"tgId"`
	Tests []oneStepTestResponse `json:"tests"`
}

type oneStepTestResponse struct {
	ID     uint64 `json:"tcId"`
	KeyOut string `json:"dkm,omitempty"`        // For AFT
	Passed *bool  `json:"testPassed,omitempty"` // For VAL
}

type oneStepNoCounter struct{}

func (k oneStepNoCounter) Process(vectorSet []byte, m Transactable) (any, error) {
	var parsed oneStepTestVectorSet
	if err := json.Unmarshal(vectorSet, &parsed); err != nil {
		return nil, err
	}

	if parsed.Mode != "OneStepNoCounter" {
		return nil, fmt.Errorf("unexpected KDA mode %q", parsed.Mode)
	}

	var respGroups []oneStepTestGroupResponse
	for _, group := range parsed.Groups {
		group := group

		groupResp := oneStepTestGroupResponse{ID: group.ID}
		outBytes, hashName, err := group.Config.extract()
		if err != nil {
			return nil, err
		}

		var isValidationTest bool
		switch group.Type {
		case "VAL":
			isValidationTest = true
		case "AFT":
			isValidationTest = false
		default:
			return nil, fmt.Errorf("unknown test type %q", group.Type)
		}

		for _, test := range group.Tests {
			test := test
			testResp := oneStepTestResponse{ID: test.ID}

			key, salt, paramsOutBytes, err := test.Params.extract()
			if err != nil {
				return nil, err
			}
			if paramsOutBytes != outBytes {
				return nil, fmt.Errorf("test %d in group %d: output length mismatch: %d != %d", test.ID, group.ID, paramsOutBytes, outBytes)
			}

			uData, err := test.FixedInfoPartyU.data()
			if err != nil {
				return nil, err
			}
			vData, err := test.FixedInfoPartyV.data()
			if err != nil {
				return nil, err
			}

			info := make([]byte, 0, len(uData)+len(vData))
			info = append(info, uData...)
			info = append(info, vData...)
			var expected []byte
			if isValidationTest {
				expected, err = hex.DecodeString(test.DerivedKeyHex)
				if err != nil {
					return nil, fmt.Errorf("test %d in group %d: invalid DerivedKeyHex: %w", test.ID, group.ID, err)
				}
			}

			cmd := "OneStepNoCounter/" + hashName
			m.TransactAsync(cmd, 1, [][]byte{key, info, salt, uint32le(outBytes)}, func(result [][]byte) error {
				if len(result[0]) != int(outBytes) {
					return fmt.Errorf("OneStepNoCounter operation resulted in %d bytes but wanted %d", len(result[0]), outBytes)
				}

				if isValidationTest {
					passed := bytes.Equal(expected, result[0])
					testResp.Passed = &passed
				} else {
					testResp.KeyOut = hex.EncodeToString(result[0])
				}

				groupResp.Tests = append(groupResp.Tests, testResp)
				return nil
			})
		}

		m.Barrier(func() {
			respGroups = append(respGroups, groupResp)
		})
	}

	if err := m.Flush(); err != nil {
		return nil, err
	}

	return respGroups, nil
}
