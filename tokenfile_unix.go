//go:build unix

package main

// Unix part of --token-file (TOK-2): open without following a symbolic link,
// then check ownership and mode on the open descriptor, and check that no
// folder on the way can be used to swap the file. See loadOrCreateToken in main.go.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// openTokenFile opens path read-only. O_NOFOLLOW makes a symbolic link fail
// instead of being followed; O_NONBLOCK keeps a FIFO planted at path from
// blocking the start (checkTokenFileInfo then refuses it as not regular).
func openTokenFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// checkTokenFileInfo checks the opened file: a regular file of the current
// user that nobody else may read or write (like ssh with a private key).
func checkTokenFileInfo(path string, fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("--token-file: %s is not a regular file", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("--token-file: cannot check the owner of %s", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("--token-file: %s belongs to another user; delete it or choose another path", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("--token-file: %s can be read or written by other users; run: chmod 600 %s", path, path)
	}
	return nil
}

// checkTokenDir checks the folder that holds the token file and every folder
// above it, like ssh with StrictModes: each must be owned by the user or by
// root and must not be writable by group or others — except with the sticky
// bit (like /tmp), where only the owner of an entry may rename or delete it.
// Otherwise anybody with write access to one of these folders could swap the
// folder below it (or the file itself) and plant a token they know.
//
// Symbolic links on the way are followed, but each link must belong to the
// user or root, and the folders of every link target are checked the same
// way. The chain is checked after MkdirAll, so folders the proxy creates
// itself (0700) are covered too.
func checkTokenDir(dir string) error {
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("--token-file: cannot check the folder %s: %v", dir, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("--token-file: %s is not a folder", dir)
	}
	// The folder itself keeps its own message (chmod 700 is the right fix
	// there); the folders above it get a separate one.
	if err := checkTokenFolder(dir, fi, true); err != nil {
		return err
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("--token-file: cannot check the folder %s: %v", dir, err)
	}

	seen := map[string]bool{}
	for _, p := range pathPrefixes(dir) {
		lfi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("--token-file: cannot check the folder %s: %v", p, err)
		}
		if lfi.Mode()&os.ModeSymlink != 0 {
			if err := checkOwner(p, lfi, "the symbolic link %s on the way to the token file belongs to another user; choose a path of your own"); err != nil {
				return err
			}
		}
		// The real location of this prefix and all folders above it.
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil {
			return fmt.Errorf("--token-file: cannot check the folder %s: %v", p, err)
		}
		for _, q := range pathPrefixes(resolved) {
			if seen[q] {
				continue
			}
			seen[q] = true
			qfi, err := os.Stat(q)
			if err != nil {
				return fmt.Errorf("--token-file: cannot check the folder %s: %v", q, err)
			}
			if !qfi.IsDir() {
				return fmt.Errorf("--token-file: %s is not a folder", q)
			}
			if q == dir || q == realDir {
				continue // checked above
			}
			if err := checkTokenFolder(q, qfi, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkTokenFolder applies the owner and write rules to one folder. own is
// true for the folder that directly holds the token file.
func checkTokenFolder(dir string, fi os.FileInfo, own bool) error {
	ownerMsg := "the folder %s above the token file belongs to another user; choose a folder of your own"
	if own {
		ownerMsg = "the folder %s belongs to another user; choose a folder of your own"
	}
	if err := checkOwner(dir, fi, ownerMsg); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		if own {
			return fmt.Errorf("--token-file: other users can write to the folder %s; run: chmod 700 %s", dir, dir)
		}
		return fmt.Errorf("--token-file: other users can write to the folder %s above the token file and could swap the folders below it; run: chmod go-w %s, or choose another place", dir, dir)
	}
	return nil
}

// checkOwner refuses fi unless it belongs to the current user or to root.
// msg has one %s for the path.
func checkOwner(path string, fi os.FileInfo, msg string) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("--token-file: cannot check the owner of %s", path)
	}
	if uid := int(st.Uid); uid != os.Getuid() && uid != 0 {
		return fmt.Errorf("--token-file: "+msg, path)
	}
	return nil
}

// pathPrefixes returns "/", "/a", "/a/b", … up to the cleaned absolute path p.
func pathPrefixes(p string) []string {
	p = filepath.Clean(p)
	out := []string{string(filepath.Separator)}
	cur := ""
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur += string(filepath.Separator) + part
		out = append(out, cur)
	}
	return out
}

// tokenPathWarning has no Unix case: the checks above are fatal instead.
func tokenPathWarning(string) string { return "" }
