package main

import (
	"encoding/hex"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// This file holds the helpers for the combined "-init ... -mount ..."
// invocation. The actual orchestration is a two-pass loop in main(): the first
// pass processes the init section, the second pass processes the mount section,
// both through the normal argument and action handling in main().

// initMountPositions holds the index of the "-init" and "-mount" tokens in the
// raw command line (os.Args).
type initMountPositions struct {
	initPos  int
	mountPos int
}

// flagTokenIndex returns the index of the first argument in osArgs that exactly
// matches one of the given flag spellings (e.g. "-init" or "--init"). It stops
// at a standalone "--", which disables option parsing. Returns -1 if not found.
func flagTokenIndex(osArgs []string, names ...string) int {
	for i, a := range osArgs {
		if a == "--" {
			return -1
		}
		for _, n := range names {
			if a == n {
				return i
			}
		}
	}
	return -1
}

// detectInitMount reports whether the command line is a combined
// "-init ... -mount ..." invocation and returns the positions of the two flags.
// ok is true only if BOTH flags are present.
func detectInitMount(osArgs []string) (pos initMountPositions, ok bool) {
	pos.initPos = flagTokenIndex(osArgs, "-init", "--init")
	pos.mountPos = flagTokenIndex(osArgs, "-mount", "--mount")
	return pos, pos.initPos >= 0 && pos.mountPos >= 0
}

// initSectionArgs returns the argument set for the init pass of a combined
// call: [prog] followed by everything from "-init" up to (but not including)
// "-mount".
func initSectionArgs(osArgs []string, pos initMountPositions) []string {
	return append([]string{osArgs[0]}, osArgs[pos.initPos:pos.mountPos]...)
}

// buildMountArgs constructs the argument set for the mount pass of a combined
// call. It is a normal mount command line:
//
//	[prog, CIPHERDIR, MOUNTPOINT, <mount-options>]
//
// The "-mount" token is replaced by the cipherdir produced by the init pass,
// and any "-masterkey" in the mount section is resolved against the init
// masterkey (see resolveMountMasterkey).
func buildMountArgs(osArgs []string, pos initMountPositions, cipherdir, initMasterkey string) []string {
	mountSection := resolveMountMasterkey(osArgs[pos.mountPos+1:], initMasterkey)
	return append([]string{osArgs[0], cipherdir}, mountSection...)
}

// resolveMountMasterkey processes the "-masterkey" option found in the
// mount-section tokens of a combined "-init ... -mount ..." command line, given
// the masterkey value (raw string) that was passed to the init section.
//
//   - A bare "-masterkey" (no value) reuses initMasterkey. This requires that
//     the init section was given an explicit "-masterkey <key>"; otherwise it is
//     a fatal usage error.
//   - An explicit "-masterkey=<key>" or "-masterkey <key>" must match
//     initMasterkey. A different value is rejected so the combined call fails
//     instead of mounting with a key that does not match the freshly
//     initialized filesystem.
//
// Returns the possibly-rewritten mount-section tokens.
func resolveMountMasterkey(mountTokens []string, initMasterkey string) []string {
	out := make([]string, 0, len(mountTokens))
	for i := 0; i < len(mountTokens); i++ {
		t := mountTokens[i]
		// Stop processing options after a standalone "--".
		if t == "--" {
			out = append(out, mountTokens[i:]...)
			break
		}
		// Explicit "=" form: -masterkey=VALUE / --masterkey=VALUE.
		if v, ok := masterkeyEqValue(t); ok {
			requireMatchingMasterkey(v, initMasterkey)
			out = append(out, t)
			continue
		}
		// Bare token: -masterkey / --masterkey.
		if t == "-masterkey" || t == "--masterkey" {
			// Explicit space form "-masterkey VALUE": the next token looks like
			// a masterkey value. Keep both tokens and verify the value matches.
			if i+1 < len(mountTokens) && looksLikeMasterkeyValue(mountTokens[i+1]) {
				requireMatchingMasterkey(mountTokens[i+1], initMasterkey)
				out = append(out, t, mountTokens[i+1])
				i++
				continue
			}
			// Bare "-masterkey": reuse the init masterkey value.
			if initMasterkey == "" {
				tlog.Fatal.Printf("-masterkey in the -mount section requires -masterkey <key> in the -init section")
				os.Exit(exitcodes.Usage)
			}
			out = append(out, "-masterkey="+initMasterkey)
			continue
		}
		out = append(out, t)
	}
	return out
}

// masterkeyEqValue returns the value of a "-masterkey=VALUE" / "--masterkey=VALUE"
// token, and ok=true if tok is such a token.
func masterkeyEqValue(tok string) (value string, ok bool) {
	for _, p := range []string{"-masterkey=", "--masterkey="} {
		if strings.HasPrefix(tok, p) {
			return tok[len(p):], true
		}
	}
	return "", false
}

// looksLikeMasterkeyValue reports whether tok looks like a value accepted by
// "-masterkey": the literal "stdin", or a hex-encoded key of the expected
// length (optionally grouped with dashes). This lets us tell an explicit
// "-masterkey <key>" apart from a bare "-masterkey" followed by the mountpoint.
func looksLikeMasterkeyValue(tok string) bool {
	if tok == "stdin" {
		return true
	}
	s := strings.Replace(tok, "-", "", -1)
	if len(s) != cryptocore.KeyLen*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// requireMatchingMasterkey verifies that an explicit masterkey value given in
// the mount section matches the one given in the init section. A mismatch is a
// fatal error so the combined call fails rather than mounting with a key that
// does not match the freshly initialized filesystem.
func requireMatchingMasterkey(mountValue, initMasterkey string) {
	// Nothing to compare against, or a value we cannot compare without side
	// effects (reading stdin): leave it to the normal mount path.
	if initMasterkey == "" || mountValue == "stdin" || initMasterkey == "stdin" {
		return
	}
	norm := func(s string) string {
		return strings.ToLower(strings.Replace(s, "-", "", -1))
	}
	if norm(mountValue) != norm(initMasterkey) {
		tlog.Fatal.Printf("-masterkey value in the -mount section does not match the -masterkey value in the -init section")
		os.Exit(exitcodes.MasterKey)
	}
}

