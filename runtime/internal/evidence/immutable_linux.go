//go:build linux

package evidence

import (
	"os"
	"syscall"
	"unsafe"
)

// The ext4/xfs inode flag ioctls. The runtime image is distroless (no chattr binary), so the
// immutable flag is set through the kernel interface directly. Setting or clearing FS_IMMUTABLE_FL
// needs CAP_LINUX_IMMUTABLE; once set, no process — root included — can write, truncate, rename or
// unlink the file until a process holding the capability clears it. That kernel rule is the privilege
// boundary between the evidence store (holds the capability) and the committer (does not).
const (
	fsIocGetFlags  = 0x80086601
	fsIocSetFlags  = 0x40086602
	fsImmutableFl  = 0x00000010
	fsAppendOnlyFl = 0x00000020
)

func getFlags(f *os.File) (int, error) {
	var flags int
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(fsIocGetFlags), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return 0, errno
	}
	return flags, nil
}

func setFlags(f *os.File, flags int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(fsIocSetFlags), uintptr(unsafe.Pointer(&flags)))
	if errno != 0 {
		return errno
	}
	return nil
}

// SetImmutable sets FS_IMMUTABLE_FL on path. Returns the kernel's error (EPERM without the
// capability, ENOTTY/EOPNOTSUPP on filesystems without inode flags such as 9p or overlay).
func SetImmutable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	flags, err := getFlags(f)
	if err != nil {
		return err
	}
	return setFlags(f, flags|fsImmutableFl)
}

// IsImmutable reports whether FS_IMMUTABLE_FL is set on path. An error means the filesystem cannot
// answer (no inode flags), which callers must treat as "not immutable".
func IsImmutable(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	flags, err := getFlags(f)
	if err != nil {
		return false, err
	}
	return flags&fsImmutableFl != 0, nil
}
