package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/songgao/water"
)

func numThreads() int {
	st, err := os.Stat("/proc/self/task")
	if err != nil {
		log.Fatal("stat: ", err)
	}
	return int(st.Sys().(*syscall.Stat_t).Nlink)
}

func Main() error {
	var args struct {
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	log.Println(os.Args)

	var err error

	// first we re-exec ourselves in a new user namespace
	if os.Args[0] != "/proc/self/exe" {
		log.Println("re-execing...")
		// launch a subprocess -- we are already in the network namespace so nothing special here
		cmd := exec.Command("/proc/self/exe")
		cmd.Args = append([]string{"/proc/self/exe"}, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			}},
			GidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			}},
		}
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error re-exec'ing ourselves in a new user namespace: %w", err)
		}
		return nil
	}

	log.Println("at the inner level, creating a tun device...")

	// create a tun device in the new namespace
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: "tun",
		},
	})
	if err != nil {
		return fmt.Errorf("error creating tun device: %w", err)
	}

	_ = tun

	// run a subprocess
	// set up environment variables for the subprocess
	env := append(
		os.Environ(),
		"PS1=HTTPTAP # ",
		"HTTPTAP=1",
	)

	log.Println("would run:", args.Command)

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
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
