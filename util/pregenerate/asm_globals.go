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

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
)

// CollectAsmGlobals collects assembly global symbols, deduplicated and sorted.
// Inputs are paths to both original and fully templated assembly source files,
// including GAS assembly source .S and NASM .asm files.
// It will understand symbols prefixed with double underscores as private,
// symbols prefixed with a *single* underscore as public on Apple platforms.
func CollectAsmGlobals(srcs []string) ([]string, error) {
	syms := make(map[string]bool)
	for _, src := range srcs {
		var file *os.File
		file, err := os.Open(src)
		if err != nil {
			return nil, err
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()
			tokens := bytes.Fields(line)
			if len(tokens) < 2 {
				continue
			}
			directive := strings.ToLower(string(tokens[0]))
			sym := string(tokens[1])
			switch directive {
			case ".global", "global", ".globl", ".extern", "extern":
				if strings.HasPrefix(sym, "__") {
					continue
				}
				sym := strings.TrimPrefix(sym, "_")
				if _, exists := syms[sym]; !exists {
					syms[sym] = true
				}
			}
		}
	}
	var ret []string
	for sym := range syms {
		ret = append(ret, sym)
	}
	slices.Sort(ret)
	return ret, nil
}

// BuildAsmGlobalsCHeader builds a symbol prefixing header for C.
func BuildAsmGlobalsCHeader(syms []string) []byte {
	var output bytes.Buffer
	writeHeader(&output, "//")
	output.WriteString("\n")
	for _, sym := range syms {
		fmt.Fprintf(&output, "#define %s BORINGSSL_ADD_PREFIX(%s)\n", sym, sym)
	}
	return output.Bytes()
}

// BuildAsmGlobalsGasHeader builds a symbol prefixing header for the GNU Assembler (gas).
func BuildAsmGlobalsGasHeader(syms []string) []byte {
	var output bytes.Buffer
	writeHeader(&output, "//")
	output.WriteString("\n")
	fmt.Fprintf(&output, "#if defined(__APPLE__)\n")
	output.WriteString("\n")
	for _, sym := range syms {
		fmt.Fprintf(&output, "#define _%s BORINGSSL_SYMBOL(BORINGSSL_ADD_PREFIX(%s))\n", sym, sym)
	}
	output.WriteString("\n")
	fmt.Fprintf(&output, "#else  // __APPLE__\n")
	output.WriteString("\n")
	for _, sym := range syms {
		fmt.Fprintf(&output, "#define %s BORINGSSL_ADD_PREFIX(%s)\n", sym, sym)
	}
	output.WriteString("\n")
	fmt.Fprintf(&output, "#endif  // __APPLE__\n")
	return output.Bytes()
}

// BuildAsmGlobalsNasmHeader builds a symbol prefixing header for the Netwide Assembler (nasm).
func BuildAsmGlobalsNasmHeader(syms []string) []byte {
	var output bytes.Buffer
	writeHeader(&output, ";")
	output.WriteString("\n")
	for _, sym := range syms {
		fmt.Fprintf(&output, "%%define _%s BORINGSSL_SYMBOL(BORINGSSL_ADD_PREFIX(%s))\n", sym, sym)
	}
	return output.Bytes()
}
