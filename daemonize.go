package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// The child sends us USR1 if the mount was successful. Exit with error code
// 0 if we get it.
func exitOnUsr1() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGUSR1)
	go func() {
		<-c
		os.Exit(0)
	}()
}

// forkChild - execute ourselves once again, this time with the "-fg" flag, and
// wait for SIGUSR1 or child exit.
// This is a workaround for the missing true fork function in Go.
//
// osArgs is the command line to re-execute. For a normal mount it is os.Args;
// for the mount pass of a combined "-init ... -mount ..." call it is the
// rewritten mount command line. If password is non-nil it is written to the
// child's stdin (and then wiped), so the child can reuse the password captured
// during the init pass; otherwise the child inherits our stdin.
func forkChild(osArgs []string, password []byte) int {
	name := os.Args[0]
	// Use the full path to our executable if we can get if from /proc.
	buf := make([]byte, syscallcompat.PATH_MAX)
	n, err := syscall.Readlink("/proc/self/exe", buf)
	if err == nil {
		name = string(buf[:n])
		tlog.Debug.Printf("forkChild: readlink worked: %q", name)
	}
	newArgs := []string{"-fg", fmt.Sprintf("-notifypid=%d", os.Getpid())}
	newArgs = append(newArgs, osArgs[1:]...)
	c := exec.Command(name, newArgs...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	var childStdin io.WriteCloser
	if password != nil {
		// Hand the captured init password to the child through a stdin pipe.
		// The child reads it via the normal stdin password path (a pipe is not
		// a terminal).
		childStdin, err = c.StdinPipe()
		if err != nil {
			tlog.Fatal.Printf("forkChild: stdin pipe failed: %v", err)
			return exitcodes.ForkChild
		}
	} else {
		c.Stdin = os.Stdin
	}
	exitOnUsr1()
	err = c.Start()
	if err != nil {
		tlog.Fatal.Printf("forkChild: starting %s failed: %v", name, err)
		return exitcodes.ForkChild
	}
	if childStdin != nil {
		childStdin.Write(password)
		childStdin.Write([]byte("\n"))
		childStdin.Close()
		for i := range password {
			password[i] = 0
		}
	}
	err = c.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if waitstat, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(waitstat.ExitStatus())
			}
		}
		tlog.Fatal.Printf("forkChild: wait returned an unknown error: %v", err)
		return exitcodes.ForkChild
	}
	// The child exited with 0 - let's do the same.
	return 0
}

// redirectStdFds redirects stderr and stdout to syslog; stdin to /dev/null
func redirectStdFds() {
	// Create a pipe pair "pw" -> "pr" and start logger reading from "pr".
	// We do it ourselves instead of using StdinPipe() because we need access
	// to the fd numbers.
	pr, pw, err := os.Pipe()
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not create pipe: %v\n", err)
		return
	}
	tag := fmt.Sprintf("gocryptfs-%d-logger", os.Getpid())
	cmd := exec.Command("logger", "-t", tag)
	cmd.Stdin = pr
	err = cmd.Start()
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not start logger: %v\n", err)
		return
	}
	// The logger now reads on "pr". We can close it.
	pr.Close()
	// Redirect stout and stderr to "pw".
	err = syscallcompat.Dup3(int(pw.Fd()), 1, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdout dup error: %v\n", err)
	}
	syscallcompat.Dup3(int(pw.Fd()), 2, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stderr dup error: %v\n", err)
	}
	// Our stdout and stderr point to "pw". We can close the original copy.
	pw.Close()
	// Redirect stdin to /dev/null
	nullFd, err := os.Open("/dev/null")
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: could not open /dev/null: %v\n", err)
		return
	}
	err = syscallcompat.Dup3(int(nullFd.Fd()), 0, 0)
	if err != nil {
		tlog.Warn.Printf("redirectStdFds: stdin dup error: %v\n", err)
	}
	nullFd.Close()
}
