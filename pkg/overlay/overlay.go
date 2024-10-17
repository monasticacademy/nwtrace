// package overlay mounts an overlay filesystem over an existing directory. Can be anywhere and no need for pivot_root.

package overlay

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Bakeable stamps itself out onto a temporary directory
type Bakeable interface {
	Bake(dir string) error
}

// file replaces the contents of a file in the original filesystem with fixed contents
type file struct {
	path    string
	content []byte
	perm    os.FileMode
}

// Bake implements Bakeable.Bake for individual files
func (f *file) Bake(dir string) error {
	path := filepath.Join(dir, f.path)

	err := os.MkdirAll(filepath.Dir(path), f.perm)
	if err != nil {
		return err
	}

	return os.WriteFile(path, f.content, f.perm)
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
}

// Remove cleans up the temporary directory created by Pivot
func (m *Remover) Remove() error {
	return os.RemoveAll(m.tmpdir)
}

func Mount(path string, nodes ...Bakeable) (*Remover, error) {
	// create a temporary directory
	tmpdir, err := os.MkdirTemp("", "overlay-*")
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory")
	}

	// prepare some paths for the main mount syscall
	workdir := filepath.Join(tmpdir, "work")   // the overlayfs driver will use this as a working directory
	layerdir := filepath.Join(tmpdir, "layer") // this is the dir holding the "diff" that will be applied to the root

	// all of these directories need to already exist for the syscalls below
	for _, dir := range []string{layerdir, workdir} {
		err = os.MkdirAll(dir, 0777)
		if err != nil {
			return nil, fmt.Errorf("error creating directory %v: %w", dir, err)
		}
	}

	// stamp out the layer
	for _, node := range nodes {
		if err := node.Bake(layerdir); err != nil {
			return nil, fmt.Errorf("error baking %T%#v: %w", node, node, err)
		}
	}

	// switch to a new mount namespace
	err = unix.Unshare(unix.CLONE_NEWNS | unix.CLONE_FS)
	if err != nil {
		return nil, fmt.Errorf("error unsharing mounts: %w", err)
	}

	// make the root filesystem in this new namespace private, which prevents the
	// mount below from leaking into the parent namespace
	// per the man page, the first, third, and fifth arguments below are ignored
	err = unix.Mount("ignored", "/", "ignored", unix.MS_PRIVATE|unix.MS_REC, "ignored")
	if err != nil {
		return nil, fmt.Errorf("error making root filesystem private")
	}

	// mount an overlay filesystem; equivalent to:
	//
	//   sudo mount -t overlay overlay -olowerdir=<path>,upperdir=<layer>,workdir=<work> <path>
	mountopts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", path, layerdir, workdir)
	err = unix.Mount("overlay", path, "overlay", 0, mountopts)
	if err != nil {
		return nil, fmt.Errorf("error mounting overlay filesystem at %v (%q): %w", path, mountopts, err)
	}

	return &Remover{tmpdir: tmpdir}, nil
}
