//go:build unix

package main

// Unix-only checks of --token-file (TOK-2): permissions of the file and its
// folder, symbolic links, foreign owners.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTokenFile_InsecurePermissions(t *testing.T) {
	valid := strings.Repeat("0f", 24) + "\n"

	// File readable by others.
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o620, 0o602} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadOrCreateToken(path)
		if err == nil || !strings.Contains(err.Error(), "chmod 600 "+path) {
			t.Errorf("file %o: %v, want the chmod 600 hint", mode, err)
		}
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if tok, _, err := loadOrCreateToken(path); err != nil || tok+"\n" != valid {
		t.Errorf("file 0400: %q %v, want accepted", tok, err)
	}

	// Folder writable by group or others, without sticky bit — for an
	// existing and for a missing token file.
	for _, mode := range []os.FileMode{0o777, 0o775, 0o770, 0o757} {
		for _, exists := range []bool{true, false} {
			d := filepath.Join(t.TempDir(), "d")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(d, "token")
			if exists {
				if err := os.WriteFile(p, []byte(valid), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chmod(d, mode); err != nil {
				t.Fatal(err)
			}
			_, _, err := loadOrCreateToken(p)
			if err == nil || !strings.Contains(err.Error(), "chmod 700 "+d) {
				t.Errorf("folder %o (file exists %t): %v, want the chmod 700 hint", mode, exists, err)
			}
			if !exists {
				if _, err := os.Lstat(p); err == nil {
					t.Errorf("folder %o: token file was created anyway", mode)
				}
			}
		}
	}

	// Sticky folder like /tmp: allowed, because the file itself must be ours.
	d := filepath.Join(t.TempDir(), "sticky")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, created, err := loadOrCreateToken(filepath.Join(d, "token")); err != nil || !created {
		t.Errorf("sticky folder: created=%t %v, want accepted", created, err)
	}

	// MkdirAll keeps the mode of an existing folder; the check sees it.
	d = filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(filepath.Join(d, "token")); err == nil {
		t.Error("token directly in a 0777 folder was accepted")
	}

	// A file of another user (only checkable as root: chown).
	if os.Getuid() == 0 {
		p := filepath.Join(t.TempDir(), "foreign")
		if err := os.WriteFile(p, []byte(valid), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if _, _, err := loadOrCreateToken(p); err == nil || !strings.Contains(err.Error(), "another user") {
			t.Errorf("foreign file: %v", err)
		}
	}
}

// TestTokenFile_FolderChain is the regression test for review N2: not only
// the folder that holds the token file, every folder above it must be safe —
// otherwise another user swaps a folder on the way and plants a token they
// know (ssh StrictModes checks the chain the same way).
func TestTokenFile_FolderChain(t *testing.T) {
	valid := strings.Repeat("0f", 24) + "\n"

	// An open (0777, no sticky bit) folder two or three levels up: refused,
	// for a folder we create below it and for one that already exists 0700.
	for _, mode := range []os.FileMode{0o777, 0o775, 0o757} {
		open := filepath.Join(t.TempDir(), "open")
		if err := os.MkdirAll(filepath.Join(open, "mine"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(open, mode); err != nil {
			t.Fatal(err)
		}
		for _, p := range []string{
			filepath.Join(open, "sub", "token"),            // sub is created 0700 by us
			filepath.Join(open, "mine", "token"),           // mine exists 0700
			filepath.Join(open, "mine", "a", "b", "token"), // deeper
		} {
			_, _, err := loadOrCreateToken(p)
			if err == nil || !strings.Contains(err.Error(), "above the token file") || !strings.Contains(err.Error(), "chmod go-w "+open) {
				t.Errorf("open ancestor %o, %s: %v, want refused with the go-w hint", mode, p, err)
			}
			if _, err := os.Lstat(p); err == nil {
				t.Errorf("open ancestor %o: %s was created anyway", mode, p)
			}
		}
	}

	// A sticky ancestor (like /tmp) is fine: nobody else may rename our
	// folder in it.
	sticky := filepath.Join(t.TempDir(), "sticky")
	if err := os.Mkdir(sticky, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if _, created, err := loadOrCreateToken(filepath.Join(sticky, "a", "b", "token")); err != nil || !created {
		t.Errorf("sticky ancestor: created=%t %v, want accepted", created, err)
	}

	// A symbolic link on the way is followed, and the folders of its target
	// are checked: a link into an open folder is refused …
	base := t.TempDir()
	open := filepath.Join(base, "open")
	if err := os.MkdirAll(filepath.Join(open, "target"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	safe := filepath.Join(base, "safe")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(safe, "link")
	if err := os.Symlink(filepath.Join(open, "target"), link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(filepath.Join(link, "token")); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("link into an open folder: %v, want refused naming %s", err, open)
	}
	// … also when the link sits higher up and the token lies further below.
	if err := os.MkdirAll(filepath.Join(open, "target", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(filepath.Join(link, "deep", "token")); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("link high up into an open folder: %v, want refused", err)
	}

	// … while a link to a safe place works and reads the same token again.
	good := filepath.Join(base, "good")
	if err := os.MkdirAll(filepath.Join(good, "cfg"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(good, "cfg", "token"), []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	goodLink := filepath.Join(safe, "goodlink")
	if err := os.Symlink(good, goodLink); err != nil {
		t.Fatal(err)
	}
	if tok, created, err := loadOrCreateToken(filepath.Join(goodLink, "cfg", "token")); err != nil || created || tok+"\n" != valid {
		t.Errorf("link to a safe folder: %q created=%t %v, want the stored token", tok, created, err)
	}

	// The prefixes the chain is built from.
	if got := strings.Join(pathPrefixes("/a/b/../c//d/"), " "); got != "/ /a /a/c /a/c/d" {
		t.Errorf("pathPrefixes = %q", got)
	}
}

func TestTokenFile_Symlink(t *testing.T) {
	valid := strings.Repeat("0f", 24) + "\n"
	dir := t.TempDir()
	realFile := filepath.Join(dir, "real")
	if err := os.WriteFile(realFile, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}

	// A symbolic link to a valid token file is refused, not followed.
	link := filepath.Join(dir, "token")
	if err := os.Symlink(realFile, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(link); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %v, want refused", err)
	}

	// A dangling link: refused, and nothing is created through it.
	target := filepath.Join(dir, "planted")
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(target, dangling); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(dangling); err == nil {
		t.Error("dangling symlink: accepted")
	}
	if _, err := os.Lstat(target); err == nil {
		t.Error("dangling symlink: the link target was created")
	}

	// A FIFO at the path neither blocks the start nor passes.
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, _, err := loadOrCreateToken(fifo); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("fifo: %v, want refused", err)
	}
}
