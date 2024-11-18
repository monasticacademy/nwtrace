package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/alexflint/go-arg"
	"golang.org/x/sys/unix"
)

func Main() error {
	var args struct {
		User    int
		Group   int
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	// once we change uid we will lose the ability to change our own gid, but in the reverse
	// direction it works out fine, so set gid first
	err := unix.Setgid(args.Group)
	if err != nil {
		log.Printf("error switching to group %v: %v", args.Group, err)
	}

	err = unix.Setuid(args.User)
	if err != nil {
		log.Printf("error switching to user %q: %v", args.User, err)
	}

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = []string{"PS1=SETUID # ", "HTTPTAP=1"}
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
