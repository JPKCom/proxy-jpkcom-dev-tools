//go:build !unix

package main

// Non-Unix part of --token-file (TOK-2), in practice Windows. Go maps a file
// mode only to the read-only attribute there, so there is no permission check:
// the protection is the ACL of the user profile. A path outside the profile
// gets a banner warning instead (tokenPathWarning).

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func openTokenFile(path string) (*os.File, error) {
	return os.Open(path)
}

func checkTokenFileInfo(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("--token-file: %s is not a regular file", path)
	}
	return nil
}

func checkTokenDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--token-file: cannot check the folder %s: %v", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("--token-file: %s is not a folder", dir)
	}
	return nil
}

// tokenPathWarning returns a banner warning when the token file on Windows
// lies outside %LOCALAPPDATA% and %USERPROFILE% (C:\Users\Public\… is
// readable by every user), "" otherwise.
func tokenPathWarning(path string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	clean := filepath.Clean(path)
	for _, env := range []string{"LOCALAPPDATA", "USERPROFILE"} {
		base := os.Getenv(env)
		if base == "" {
			continue
		}
		base = filepath.Clean(base)
		if strings.EqualFold(clean, base) {
			continue
		}
		prefix := base
		if !strings.HasSuffix(prefix, `\`) {
			prefix += `\`
		}
		if len(clean) > len(prefix) && strings.EqualFold(clean[:len(prefix)], prefix) {
			return ""
		}
	}
	return "token file outside your user profile — other users may be able to read it"
}
