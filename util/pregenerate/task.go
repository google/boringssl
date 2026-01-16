// Copyright 2024 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

type Task interface {
	// Destination returns the destination path for this task, using forward
	// slashes and relative to the source directory. That is, use the "path"
	// package, not "path/filepath".
	Destination() string

	// Run computes the output for this task. It should be written to the
	// destination path.
	Run() ([]byte, error)
}

type WaitableTask interface {
	Task

	// Wait waits for the task to finish, and returns its status.
	Wait() error

	// Close closes this task. Waiting on it will return err.
	Close(err error)
}

// WaitableTaskImpl is an implementation of a waitable task.
type WaitableTaskImpl struct {
	Task
	FinishedC chan struct{}
	Err       error
}

func WrapWaitable(t Task) WaitableTask {
	return &WaitableTaskImpl{Task: t, FinishedC: make(chan struct{})}
}

// Run performs the task, taking care of infrastructure so it can be waited on.
func (t *WaitableTaskImpl) Run() (out []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic caught: %v", p)
		}
		t.Close(err)
	}()
	return t.Task.Run()
}

// Wait waits for the task to finish, and returns its status.
func (t *WaitableTaskImpl) Wait() error {
	<-t.FinishedC
	return t.Err
}

// Close closes the task.
func (t *WaitableTaskImpl) Close(err error) {
	t.Err = err
	close(t.FinishedC)
}

type SimpleTask struct {
	Dst     string
	RunFunc func() ([]byte, error)
}

// Destination returns where this task will write to.
func (t *SimpleTask) Destination() string { return t.Dst }

// Run performs the task.
func (t *SimpleTask) Run() ([]byte, error) { return t.RunFunc() }

// NewSimpleTask creates a new task based on a lambda for what it does.
func NewSimpleTask(dst string, runFunc func() ([]byte, error)) *SimpleTask {
	return &SimpleTask{Dst: dst, RunFunc: runFunc}
}

type PerlasmTask struct {
	Src, Dst string
	Args     []string
}

func (t *PerlasmTask) Destination() string { return t.Dst }
func (t *PerlasmTask) Run() ([]byte, error) {
	base := path.Base(t.Dst)
	out, err := os.CreateTemp("", "*."+base)
	if err != nil {
		return nil, err
	}
	defer os.Remove(out.Name())

	args := make([]string, 0, 2+len(t.Args))
	args = append(args, filepath.FromSlash(t.Src))
	args = append(args, t.Args...)
	args = append(args, out.Name())
	cmd := exec.Command(*perlPath, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(out.Name())
	if err != nil {
		return nil, err
	}

	// On Windows, perl emits CRLF line endings. Normalize this so that the tool
	// can be run on Windows too.
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return data, nil
}
