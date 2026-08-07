//go:build unix

package discover

import "syscall"

func makeFIFO(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
