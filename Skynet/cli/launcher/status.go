package main

// Native `skynet status`.
//
// 2026-08-03: status cost 1482 ms, then 767 ms after the loopback probes were
// made concurrent with a 0.3 s timeout. The residue was NOT the probes - it was
// the ~373 ms PyInstaller/CPython startup paid just to issue two localhost HTTP
// GETs. Answering here removes that entirely.
//
// Truth rules carried over from the Python implementation, deliberately:
//   - a probe that cannot be reached is "down"
//   - a probe that times out or fails to parse is "unknown", NEVER a confident
//     "down" and never healthy
//   - wall time is bounded by the slowest probe, not the sum

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// A loopback service answers in single-digit ms or is not listening at all.
const loopbackTimeout = 300 * time.Millisecond

type probe struct {
	State      string          `json:"state"`
	HTTPStatus *int            `json:"http_status"`
	Body       json.RawMessage `json:"body,omitempty"`
	Error      string          `json:"error,omitempty"`
}

type statusReport struct {
	Tool       string         `json:"tool"`
	OK         bool           `json:"ok"`
	Runtime    string         `json:"runtime"`
	Repository repositoryInfo `json:"repository"`
	Bus        probe          `json:"bus"`
	VSIX       probe          `json:"vsix"`
}

type repositoryInfo struct {
	Configured bool    `json:"configured"`
	Path       *string `json:"path"`
}

func probeJSON(url string) probe {
	client := &http.Client{Timeout: loopbackTimeout}
	resp, err := client.Get(url)
	if err != nil {
		// Unreachable loopback is a real "down"; a deadline is "unknown".
		if strings.Contains(err.Error(), "deadline exceeded") ||
			strings.Contains(err.Error(), "Client.Timeout") {
			return probe{State: "unknown", Error: "probe_timeout"}
		}
		return probe{State: "down", Error: "connection_error"}
	}
	defer resp.Body.Close()
	code := resp.StatusCode
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return probe{State: "unknown", HTTPStatus: &code, Error: "read_error"}
	}
	if !json.Valid(raw) {
		// Answered but unparseable: we do not know its health.
		return probe{State: "unknown", HTTPStatus: &code, Error: "invalid_json_response"}
	}
	return probe{State: "up", HTTPStatus: &code, Body: json.RawMessage(raw)}
}

// repoRoot mirrors the runtime's resolution: explicit env var, then cwd, then the
// launcher's own directory, walking upward for the manifest marker.
func repoRoot() *string {
	var starts []string
	if configured := os.Getenv("SKYNET_REPO_ROOT"); configured != "" {
		starts = append(starts, configured)
	}
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if self, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(self))
	}
	seen := map[string]bool{}
	for _, start := range starts {
		dir, err := filepath.Abs(start)
		if err != nil {
			continue
		}
		for {
			key := strings.ToLower(dir)
			if !seen[key] {
				seen[key] = true
				marker := filepath.Join(dir, "data", "skynet_cli_manifest.json")
				if info, err := os.Stat(marker); err == nil && !info.IsDir() {
					found := dir
					return &found
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return strings.TrimRight(value, "/")
	}
	return fallback
}

func nativeStatus(wantJSON bool) int {
	busURL := envOr("SKYNET_BUS_URL", "http://127.0.0.1:8420")
	vsixURL := envOr("SKYNET_VSIX_URL", "http://127.0.0.1:8419")

	var bus, vsix probe
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); bus = probeJSON(busURL + "/health") }()
	go func() { defer wg.Done(); vsix = probeJSON(vsixURL + "/health") }()
	wg.Wait()

	root := repoRoot()
	report := statusReport{
		Tool:       "skynet-native-status",
		OK:         bus.State == "up" || vsix.State == "up",
		Runtime:    "self-contained-go-launcher",
		Repository: repositoryInfo{Configured: root != nil, Path: root},
		Bus:        bus,
		VSIX:       vsix,
	}

	if wantJSON {
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return 1
		}
		writeStdout(string(encoded) + "\n")
		return 0
	}

	repoText := "not configured"
	if root != nil {
		repoText = *root
	}
	writeStdout("Skynet native " + version + "\n")
	writeStdout("  runtime: self-contained\n")
	writeStdout("  repository: " + repoText + "\n")
	writeStdout("  bus: " + bus.State + "  vsix: " + vsix.State + "\n")
	// Status reports reality; a down local service is not a CLI execution error.
	return 0
}
