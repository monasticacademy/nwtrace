package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"

	"github.com/alexflint/go-arg"
	"github.com/monasticacademy/httptap/pkg/bindfiles"
)

func Main() error {
	var args struct {
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}

	// lock this goroutine to a single OS thread because namespaces are thread-local
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// go to a new mount namespace and overlay the root filesystem in that namespace
	mount, err := bindfiles.Mount(
		bindfiles.File("/etc/resolv.conf", []byte("hello bindfiles\n")),
	)
	if err != nil {
		return fmt.Errorf("error bind-mounting: %w", err)
	}
	defer mount.Remove()

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
