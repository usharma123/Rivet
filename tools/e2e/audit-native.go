// audit-native is a Linux-only workload for the isolated gVisor audit tests.
// Each mode performs a real syscall path that a JavaScript hook cannot see.
package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const honey = "/tmp/rivet-work/home/.npmrc"

func main() {
	if len(os.Args) != 2 {
		fatal(fmt.Errorf("one mode required"))
	}
	var path string
	switch os.Args[1] {
	case "symlink_mmap":
		if err := os.Symlink(honey, "./honey-alias"); err != nil {
			fatal(err)
		}
		path = "./honey-alias"
	case "proc_mmap":
		path = "/proc/self/root" + honey
	case "double_slash_mmap":
		path = "/" + honey
	case "openat2_mmap":
		openat2Mmap()
		return
	case "unshare":
		_, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, uintptr(syscall.CLONE_NEWUSER|syscall.CLONE_NEWNS), 0, 0)
		fmt.Printf("unshare errno=%d\n", errno)
		return
	case "udp_send":
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
		if err != nil {
			fatal(err)
		}
		defer syscall.Close(fd)
		err = syscall.Sendto(fd, []byte("rivet-probe"), 0, &syscall.SockaddrInet4{Port: 9, Addr: [4]byte{127, 0, 0, 1}})
		fmt.Printf("sendto err=%v\n", err)
		return
	default:
		fatal(fmt.Errorf("unknown mode %q", os.Args[1]))
	}
	f, err := os.Open(path)
	if err != nil {
		fatal(err)
	}
	defer f.Close()
	mmapHoney(f)
}

func openat2Mmap() {
	name, err := syscall.BytePtrFromString(honey)
	if err != nil {
		fatal(err)
	}
	how := struct {
		flags   uint64
		mode    uint64
		resolve uint64
	}{flags: syscall.O_RDONLY}
	fd, _, errno := syscall.RawSyscall6(437, ^uintptr(99), uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
	if errno != 0 {
		// Continue with a supported open. A missing openat2 trace must not be
		// hidden by a workload error before the trusted completion barrier.
		fmt.Printf("openat2 errno=%d\n", errno)
		f, err := os.Open(honey)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		mmapHoney(f)
		return
	}
	f := os.NewFile(fd, honey)
	defer f.Close()
	mmapHoney(f)
}

func mmapHoney(f *os.File) {
	info, err := f.Stat()
	if err != nil {
		fatal(err)
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(info.Size()), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		fatal(err)
	}
	defer syscall.Munmap(data)
	if !bytes.Contains(data, []byte("RIVETHONEYTOKEN")) {
		fatal(fmt.Errorf("honeytoken missing from mmap"))
	}
	fmt.Println("mmap read honeytoken")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
