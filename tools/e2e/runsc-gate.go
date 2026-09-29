// runsc-gate is a setuid helper for the isolated audit integration test.
// It permits two read-only runsc queries against one full container ID.
// Build with CGO_ENABLED=0, install root-owned mode 4755 inside the disposable
// Docker-in-Docker container, and never install it on a production host.
package main

import (
	"fmt"
	"os"
	"regexp"
	"syscall"
)

var containerID = regexp.MustCompile(`^[a-f0-9]{64}$`)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if err := syscall.Exec("/runsc/runsc", []string{"/runsc/runsc", "--version"}, []string{"PATH=/usr/bin:/bin"}); err != nil {
			die(err.Error())
		}
		return
	}
	if len(os.Args) != 5 || os.Args[1] != "--root=/var/run/docker/runtime-runc/moby" || !containerID.MatchString(os.Args[4]) {
		die("invalid runsc query")
	}
	var args []string
	switch {
	case os.Args[2] == "trace" && os.Args[3] == "list":
		args = []string{"/runsc/runsc", "--allow-flag-override", os.Args[1], "trace", "list", os.Args[4]}
	case os.Args[2] == "ps" && os.Args[3] == "-format=json":
		args = []string{"/runsc/runsc", "--allow-flag-override", os.Args[1], "ps", "-format=json", os.Args[4]}
	default:
		die("invalid runsc query")
	}
	if os.Geteuid() != 0 {
		die("helper must be root-owned mode 4755")
	}
	if err := syscall.Setreuid(0, 0); err != nil {
		die(err.Error())
	}
	if err := syscall.Exec("/runsc/runsc", args, []string{"PATH=/usr/bin:/bin"}); err != nil {
		die(err.Error())
	}
}

func die(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
