//go:build !linux

package evidence

import "errors"

var errNoInodeFlags = errors.New("inode immutability flags are a Linux filesystem feature")

// SetImmutable is unavailable off Linux (development on Windows/macOS); the store records that the
// segment is sealed but cannot make it immutable. Production runs in the Linux container.
func SetImmutable(path string) error { return errNoInodeFlags }

func IsImmutable(path string) (bool, error) { return false, errNoInodeFlags }

func ClearImmutable(path string) error { return nil }
