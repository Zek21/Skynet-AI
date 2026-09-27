package main

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
)

var version = "dev"

const launcherIdentity = "SKYNET_GO_LAUNCHER_V1"

func writeStdout(value string) { _, _ = os.Stdout.WriteString(value) }
func writeStderr(value string) { _, _ = os.Stderr.WriteString(value) }

func formatHelp() string {
	// Avoid fmt on the cold path while retaining the runtime's exact help text.
	const marker = "%s"
	for i := 0; i+len(marker) <= len(helpText); i++ {
		if helpText[i:i+len(marker)] == marker {
			return helpText[:i] + version + helpText[i+len(marker):]
		}
	}
	return helpText
}

func native(args []string) bool {
	if len(args) == 1 {
		switch args[0] {
		case "--version", "-v", "-V", "version":
			writeStdout("skynet " + version + "\n")
			return true
		case "--help":
			writeStdout(formatHelp())
			return true
		case "commands":
			writeStdout(commandsText)
			return true
		}
	}
	if len(args) == 1 && args[0] == "--skynet-launcher-identity" {
		writeStdout(launcherIdentity + "\n")
		return true
	}
	if len(args) == 2 && args[0] == "commands" && args[1] == "--json" {
		writeStdout(commandsJSON)
		return true
	}
	return false
}

// statusExit is set when `status` is answered natively, so run() can propagate
// its code without pretending every native command exits 0.
var statusExit = -1

func nativeStatusCommand(args []string) bool {
	if len(args) == 1 && args[0] == "status" {
		statusExit = nativeStatus(false)
		return true
	}
	if len(args) == 2 && args[0] == "status" && args[1] == "--json" {
		statusExit = nativeStatus(true)
		return true
	}
	return false
}

func runtimePath() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(self), "skynet-runtime.exe"), nil
}

func run() int {
	if native(os.Args[1:]) {
		return 0
	}
	if nativeStatusCommand(os.Args[1:]) {
		return statusExit
	}
	runtime, err := runtimePath()
	if err != nil {
		writeStderr("skynet: cannot determine launcher path: " + err.Error() + "\n")
		return 125
	}
	if _, err = os.Stat(runtime); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			writeStderr("skynet: runtime missing: " + runtime + "\n")
			return 127
		}
		writeStderr("skynet: cannot access runtime: " + err.Error() + "\n")
		return 126
	}
	cmd := exec.Command(runtime, os.Args[1:]...)
	cmd.Args[0] = os.Args[0]
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	err = cmd.Run()
	signal.Stop(interrupts)
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	writeStderr("skynet: cannot execute runtime: " + err.Error() + "\n")
	return 126
}

func main() { os.Exit(run()) }
