package cli

import (
	"fmt"
	"os/exec"
	"runtime"
)

// openInBrowser opens a local file in the user's default browser. It shells out
// to the platform opener; if none is available the caller reports the path so
// the user can open it manually. The report is a static file — no server runs.
func openInBrowser(path string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{path}
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", path}
	default: // linux, bsd, ...
		cmd, args = "xdg-open", []string{path}
	}
	if _, err := exec.LookPath(cmd); err != nil {
		return fmt.Errorf("no opener (%s) found", cmd)
	}
	return exec.Command(cmd, args...).Start()
}
