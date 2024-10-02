// package overlayroot modifies the view of the root filesystem accessible to the current process

package overlayroot

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Bakeable stamps itself out onto a temporary directory
type Bakeable interface {
	Bake(overlayroot string) error
}

// file replaces the contents of a file in the original filesystem with fixed contents
type file struct {
	path    string
	content []byte
	perm    os.FileMode
}

// Bake implements Bakeable.Bake for individual files
func (f *file) Bake(overlayroot string) error {
	path := filepath.Join(overlayroot, f.path)

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

func Pivot(nodes ...Bakeable) (*Remover, error) {
	// create a temporary directory
	tmpdir, err := os.MkdirTemp("", "overlay-root-*")
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory")
	}

	// prepare some paths for the main mount syscall
	newroot := filepath.Join(tmpdir, "merged") // this will be mounted as an overlayfs
	oldroot := filepath.Join(newroot, "old")   // this is where the old root will be put by pivot_root
	workdir := filepath.Join(tmpdir, "work")   // the overlayfs driver will use this as a working directory
	layerdir := filepath.Join(tmpdir, "layer") // this is the dir holding the "diff" that will be applied to the root

	// all of these directories need to already exist for the syscalls below
	for _, dir := range []string{newroot, oldroot, layerdir, workdir} {
		err = os.MkdirAll(dir, os.ModePerm)
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

	// mount an overlay filesystem
	// sudo mount -t overlay overlay -olowerdir=$(pwd)/lower,upperdir=$(pwd)/upper,workdir=$(pwd)/work $(pwd)/merged
	mountopts := fmt.Sprintf("lowerdir=/,upperdir=%s,workdir=%s", layerdir, workdir)
	err = unix.Mount("overlay", newroot, "overlay", 0, mountopts)
	if err != nil {
		return nil, fmt.Errorf("error mounting overlay filesystem: %w", err)
	}

	// set the root of the filesystem to the overlay
	err = unix.PivotRoot(newroot, oldroot)
	if err != nil {
		return nil, fmt.Errorf("error changing root of filesystem to %v: %w", newroot, err)
	}

	return &Remover{tmpdir: tmpdir}, nil
}

func Mount(nodes ...Bakeable) (*Remover, error) {
	// create a temporary directory
	tmpdir, err := os.MkdirTemp("", "overlay-root-*")
	if err != nil {
		return nil, fmt.Errorf("error getting current working directory")
	}

	// prepare some paths for the main mount syscall
	newroot := filepath.Join(tmpdir, "merged") // this will be mounted as an overlayfs
	oldroot := filepath.Join(newroot, "old")   // this is where the old root will be put by pivot_root
	workdir := filepath.Join(tmpdir, "work")   // the overlayfs driver will use this as a working directory
	layerdir := filepath.Join(tmpdir, "layer") // this is the dir holding the "diff" that will be applied to the root

	// all of these directories need to already exist for the syscalls below
	for _, dir := range []string{newroot, oldroot, layerdir, workdir} {
		err = os.MkdirAll(dir, os.ModePerm)
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

	// mount an overlay filesystem
	// sudo mount -t overlay overlay -olowerdir=$(pwd)/lower,upperdir=$(pwd)/upper,workdir=$(pwd)/work $(pwd)/merged
	mountopts := fmt.Sprintf("lowerdir=/,upperdir=%s,workdir=%s", layerdir, workdir)
	err = unix.Mount("overlay", newroot, "overlay", 0, mountopts)
	if err != nil {
		return nil, fmt.Errorf("error mounting overlay filesystem: %w", err)
	}

	log.Printf("mounted overlay at %v", newroot)

	return &Remover{tmpdir: tmpdir}, nil
}
