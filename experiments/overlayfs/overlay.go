package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/alexflint/go-arg"
	"golang.org/x/sys/unix"
)

func Main() error {
	var args struct {
		Command []string `arg:"positional"`
	}
	arg.MustParse(&args)

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	lowerdir := filepath.Join(cwd, "lower")
	upperdir := filepath.Join(cwd, "upper")
	workdir := filepath.Join(cwd, "work")
	mergedir := filepath.Join(cwd, "merged")

	for _, dir := range []string{lowerdir, upperdir, workdir, mergedir} {
		_ = os.MkdirAll(dir, os.ModeDir)
	}

	// mount an overlay filesystem
	// sudo mount -t overlay overlay -olowerdir=$(pwd)/lower,upperdir=$(pwd)/upper,workdir=$(pwd)/work $(pwd)/merged
	mountopts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerdir, upperdir, workdir)
	err = unix.Mount("overlay", mergedir, "overlay", 0, mountopts)
	if err != nil {
		return fmt.Errorf("error mounting overlay filesystem: %w", err)
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
