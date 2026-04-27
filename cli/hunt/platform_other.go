//go:build !linux

package hunt

import "os/exec"

func setSysProcAttr(cmd *exec.Cmd) {}

func killProcess(cmd *exec.Cmd) {
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
}
