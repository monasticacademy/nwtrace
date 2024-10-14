package main

import (
	"runtime/debug"
)

func handlePanic() {
	if r := recover(); r != nil {
		errorf("%v", r)
		errorf(string(debug.Stack()))
	}
}

func goHandlePanic(f func() error) {
	defer handlePanic()
	err := f()
	if err != nil {
		errorf("a goroutine exited with: %v", err)
	}
}
