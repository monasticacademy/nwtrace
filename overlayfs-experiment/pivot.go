package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/alexflint/go-arg"
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

// Bake implements Bakeable.Bake
func (f *file) Bake(overlayroot string) error {
	path := filepath.Join(overlayroot, f.path)

	err := os.MkdirAll(filepath.Dir(path), f.perm)
	if err != nil {
		return err
	}

	return os.WriteFile(path, f.content, f.perm)
}

func StringFile(path string, content string) *file {
	return &file{path: path, content: []byte(content), perm: 0700}
}

// Mount is a pivot_root'ed overlay filesystem. The main purpose of this struct
// is to facilitate cleaning it up afterwards.
type Mount struct {
	tmpdir string
}

func (m *Mount) Remove() error {
	return os.RemoveAll(m.tmpdir)
}

func OverlayRoot(nodes ...Bakeable) (*Mount, error) {
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
		err = os.MkdirAll(dir, 0700)
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

	return &Mount{tmpdir: tmpdir}, nil
}

func Main() error {
	var args struct {
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	var err error

	// lock this goroutine to a single OS thread because namespaces are thread-local
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// go to a new mount namespace and overlay the root filesystem in that namespace
	mount, err := OverlayRoot(
		StringFile("/a/b/test", "hello overlay root\n"),
	)
	if err != nil {
		return fmt.Errorf("error overlaying root filesystem: %w", err)
	}
	defer mount.Remove()

	log.Println(mount.tmpdir)

	// launch a subprocess -- we are already in the namespace so no need for CLONE_NS here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PS1=MOUNTNAMESPACE # "}
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// wait for subprocess completion
	err = cmd.Wait()
	if err != nil {
		exitError, isExitError := err.(*exec.ExitError)
		if isExitError {
			return fmt.Errorf("subprocess exited with code %d", exitError.ExitCode())
		} else {
			return fmt.Errorf("error running subprocess: %v", err)
		}
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}
