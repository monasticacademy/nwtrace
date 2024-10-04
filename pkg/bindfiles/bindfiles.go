// package bindfiles creates a mount namespace and privately within that namespace binds
// a set of files to temporary files containing certain contents. This can be used to
// create a view of an existing file system with specific modifications, without the
// permissions issues associated with pivot_root on the entire filesystem.

package bindfiles

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// file replaces the contents of a file in the original filesystem with fixed contents
type file struct {
	path    string
	content []byte
	perm    os.FileMode
}

// File is a file with contents specified by a string
func File(path string, content []byte) *file {
	return &file{path: path, content: content, perm: os.ModePerm}
}

// FilePerm is like File but you can specify the permissions
func FilePerm(path string, content []byte, perm os.FileMode) *file {
	return &file{path: path, content: content, perm: perm}
}

// Remover holds the location of certain temporary files supporting a pivot_root'ed
// overlay filesystem. The main purpose of this struct is to clean it up afterwards.
type Remover struct {
	tmpdir string
	mounts []string
}

// Remove cleans up the temporary directory and unmounts the binds
func (m *Remover) Remove() error {
	var errmsgs []string
	for _, mount := range m.mounts {
		err := unix.Unmount(mount, 0)
		if err != nil {
			errmsgs = append(errmsgs, err.Error())
		}
	}
	if len(errmsgs) > 0 {
		return fmt.Errorf("error unmounting %d binds: %v", len(errmsgs), strings.Join(errmsgs, ", "))
	}

	return os.RemoveAll(m.tmpdir)
}

func Mount(files ...*file) (*Remover, error) {
	// create a temporary directory
	tmpdir, err := os.MkdirTemp("", "overlay-root-*")
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory")
	}

	remover := Remover{tmpdir: tmpdir}

	// switch to a new mount namespace
	err = unix.Unshare(unix.CLONE_NEWNS | unix.CLONE_FS)
	if err != nil {
		return &remover, fmt.Errorf("error unsharing mounts: %w", err)
	}

	// make the root filesystem in this new namespace private, which prevents the
	// mount below from leaking into the parent namespace
	// per the man page, the first, third, and fifth arguments below are ignored
	err = unix.Mount("ignored", "/", "ignored", unix.MS_PRIVATE|unix.MS_REC, "ignored")
	if err != nil {
		return &remover, fmt.Errorf("error making root filesystem private")
	}

	// bind-mount each file
	for i, file := range files {
		path := filepath.Join(tmpdir, fmt.Sprintf("%08d_%s", i, filepath.Base(file.path)))
		err := os.WriteFile(path, file.content, file.perm)
		if err != nil {
			return &remover, fmt.Errorf("error creating temporary file for %v: %w", file.path, err)
		}

		// make sure the target exists and is a file
		st, err := os.Stat(file.path)
		if err != nil {
			return &remover, fmt.Errorf("error checking %v: %w", file.path, err)
		}
		if !st.Mode().IsRegular() {
			return &remover, fmt.Errorf("%v is not a regular file (found %v)", file.path, st.Mode())
		}

		// do the bind-mount -- third and fifth parameters below are ignored
		err = unix.Mount(path, file.path, "==ignored==", unix.MS_BIND, "==ignored==")
		if err != nil {
			return &remover, fmt.Errorf("error bind-mounting: %w", err)
		}

		remover.mounts = append(remover.mounts, file.path)
	}

	return &remover, nil
}
