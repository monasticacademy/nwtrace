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

func Main() error {
	var args struct {
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	// // lock the OS thread in order to switch namespaces (namespaces are thread-specific)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// switch to a new mount namespace
	err := unix.Unshare(unix.CLONE_FS)
	if err != nil {
		return fmt.Errorf("error unsharing mounts: %w", err)
	}

	// make the root filesystem in this new namespace private
	err = unix.Mount("ignored", "/", "ignored", unix.MS_PRIVATE, "ignored")
	if err != nil {
		return fmt.Errorf("error making root filesystem private")
	}

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current working directory")
	}

	target := filepath.Join(pwd, "merged")
	lower := filepath.Join(pwd, "lower")
	upper := filepath.Join(pwd, "upper")
	work := filepath.Join(pwd, "work")
	mountopts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)

	// sudo mount -t overlay overlay -olowerdir=$(pwd)/lower,upperdir=$(pwd)/upper,workdir=$(pwd)/work $(pwd)/merged
	err = unix.Mount("overlay", target, "overlay", 0, mountopts)
	if err != nil {
		return fmt.Errorf("error mounting overlay filesystem: %w", err)
	}

	// launch a subprocess -- we are already in the namespace so no need for CLONE_NS here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PS1=MOUNTNS # "}
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
