// (c) go2rtc

//go:build !linux

package shell

import "syscall"

var procAttr *syscall.SysProcAttr
