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
	"bytes"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"boringssl.googlesource.com/boringssl.git/util/idextractor"
)

// platformDependentRedefineExtnameSymbols is the list of symbols in the public
// headers that are not enabled on all platforms, and that can use redefine_extname.
//
// They will always be included in the prefixing headers.
var platformDependentRedefineExtnameSymbols = []string{
	"CRYPTO_has_broken_NEON",
	"CRYPTO_needs_hwcap2_workaround",
	"CRYPTO_set_fuzzer_mode",
	"RAND_enable_fork_unsafe_buffering",
	"RAND_disable_fork_unsafe_buffering",
	"RAND_reset_for_fuzzing",
}

// platformDependentRedefineExtnameSymbols is the list of symbols in the public
// headers that are not enabled on all platforms, and that must be renamed using macros.
//
// They will always be included in the prefixing headers.
var platformDependentMacroSymbols = []string{}

// isClangCL returns whether the program given is likely the `clang-cl` driver.
func isClangCL(clang string) (bool, error) {
	// We probably could be smarter here than just using the binary name.
	return strings.TrimSuffix(strings.ToLower(filepath.Base(clang)), ".exe") == "clang-cl", nil
}

// cSymbolData is data for generating the C renaming includes.
type cSymbolData struct {
	inlineDefinitions  map[string]struct{}
	externDeclarations map[string]struct{}
}

// CollectCSymbols calls Clang to extract the AST of the headers, then processes them to extract the symbols.
//
// It returns data for generating C and Rust includes.
func CollectCSymbols(headers []string) (syms cSymbolData, err error) {
	cmd := *clangPath
	if cmd == "" {
		return cSymbolData{}, fmt.Errorf("%w: clang has been disabled by flag", TaskSkipped)
	}

	defer func() {
		if err != nil {
			err = fmt.Errorf("%w; note that this step can be turned off by passing -clang=", err)
		}
	}()

	isCL, err := isClangCL(cmd)
	if err != nil {
		return cSymbolData{}, err
	}

	var args []string
	if isCL {
		// If using clang-cl.exe, args need to be in CL form.
		args = []string{
			"/TP",
			"/std:c++17",
			"/Zs",
			"-Xclang", "-ast-dump=json",
			"/I", "include",
			"-",
		}
	} else {
		// Standard Clang args.
		args = []string{
			"-x", "c++",
			"-std=c++17",
			"-fsyntax-only",
			"-Xclang", "-ast-dump=json",
			"-Iinclude",
			"-",
		}
	}

	var stdin bytes.Buffer
	for _, header := range headers {
		fmt.Fprintf(&stdin, "#include <%s>\n", strings.TrimPrefix(filepath.ToSlash(header), "include/"))
	}

	c := exec.Command(cmd, args...)
	c.Stdin = &stdin
	c.Stderr = os.Stderr

	stdout, err := c.StdoutPipe()
	if err != nil {
		return cSymbolData{}, err
	}
	defer stdout.Close()

	err = c.Start()
	if err != nil {
		return cSymbolData{}, err
	}

	syms.externDeclarations = map[string]struct{}{}
	for _, sym := range platformDependentRedefineExtnameSymbols {
		syms.externDeclarations[sym] = struct{}{}
	}

	syms.inlineDefinitions = map[string]struct{}{}
	for _, sym := range platformDependentMacroSymbols {
		syms.inlineDefinitions[sym] = struct{}{}
	}

	report := func(id idextractor.IdentifierInfo) error {
		switch id.Symbol {
		case "begin", "end":
			// Template specializations for STL use, namespaced in template arguments.
			return nil
		case id.Identifier:
			// So it's not namespaced. Proceed.
		default:
			// Already in a namespace.
			return nil
		}
		var isInline bool
		switch id.Linkage {
		case "", "static", "static inline":
			// Definitely not linked.
			return nil
		case `extern "C" inline`, `extern "C++" inline`:
			// Sorry, can't redefine_extname inline functions:
			// error: #pragma redefine_extname is applicable to external C declarations only; not applied to function
			isInline = true
		case `extern "C"`:
			// Link those.
			isInline = false
		default:
			return fmt.Errorf("unexpected linkage: %q", id.Linkage)
		}
		switch id.Tag {
		case "enumerator", "typedef", "using":
			// These never create any symbols and are safe to ignore.
			return nil
		case "class", "enum", "struct", "union":
			// These may create symbols when used as a template argument,
			// however cannot be namespaced as known callers forward declare them.
			return nil
		case "function", "var":
			if isInline {
				syms.inlineDefinitions[id.Symbol] = struct{}{}
			} else {
				syms.externDeclarations[id.Symbol] = struct{}{}
			}
			return nil
		default:
			return fmt.Errorf("unexpected tag in %+v", id)
		}
	}

	for sym := range syms.inlineDefinitions {
		if _, found := syms.externDeclarations[sym]; found {
			return cSymbolData{}, fmt.Errorf("symbol %q both marked as extern and inline type symbol renaming; please fix", sym)
		}
	}

	err = idextractor.New(report, idextractor.Options{Language: "C++"}).Parse(stdout)
	if err != nil {
		c.Process.Kill()
		return cSymbolData{}, err
	}

	err = c.Wait()
	if err != nil {
		return cSymbolData{}, err
	}

	return syms, nil
}

func BuildCRenamingInclude(syms cSymbolData) []byte {
	var output bytes.Buffer
	writeHeader(&output, "//")
	output.WriteString(`
#ifndef OPENSSL_HEADER_PREFIX_SYMBOLS_H
#define OPENSSL_HEADER_PREFIX_SYMBOLS_H


#define BORINGSSL_ADD_PREFIX_CONCAT_INNER(a, b) a##_##b
#define BORINGSSL_ADD_PREFIX_CONCAT(a, b) \
  BORINGSSL_ADD_PREFIX_CONCAT_INNER(a, b)
#define BORINGSSL_ADD_PREFIX(s) BORINGSSL_ADD_PREFIX_CONCAT(BORINGSSL_PREFIX, s)

#if defined(__APPLE__)
#define BORINGSSL_SYMBOL_INNER(s) _##s
#define BORINGSSL_SYMBOL(s) BORINGSSL_SYMBOL_INNER(s)
#else  // __APPLE__
#define BORINGSSL_SYMBOL(s) s
#endif  // __APPLE__

`)
	output.WriteString("#if defined(__PRAGMA_REDEFINE_EXTNAME)\n")
	output.WriteString("\n")
	for _, sym := range slices.Sorted(maps.Keys(syms.externDeclarations)) {
		fmt.Fprintf(&output, "#pragma redefine_extname %s BORINGSSL_SYMBOL(BORINGSSL_ADD_PREFIX(%s))\n", sym, sym)
	}
	output.WriteString("\n")
	output.WriteString("#else  // __PRAGMA_REDEFINE_EXTNAME\n")
	output.WriteString("\n")
	for _, sym := range slices.Sorted(maps.Keys(syms.externDeclarations)) {
		fmt.Fprintf(&output, "#define %s BORINGSSL_ADD_PREFIX(%s)\n", sym, sym)
	}
	output.WriteString("\n")
	output.WriteString("#endif  // __PRAGMA_REDEFINE_EXTNAME\n")
	output.WriteString("\n")
	output.WriteString("#if !defined(BORINGSSL_ALWAYS_USE_STATIC_INLINE)\n")
	output.WriteString("\n")
	for _, sym := range slices.Sorted(maps.Keys(syms.inlineDefinitions)) {
		fmt.Fprintf(&output, "#define %s BORINGSSL_ADD_PREFIX(%s)\n", sym, sym)
	}
	output.WriteString("\n")
	output.WriteString("#endif  // !BORINGSSL_ALWAYS_USE_STATIC_INLINE\n")
	output.WriteString(`
#endif  // OPENSSL_HEADER_PREFIX_SYMBOLS_H
`)
	return output.Bytes()
}
