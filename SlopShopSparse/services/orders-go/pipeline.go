package main

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Data pipeline handlers. Reviewed under SEC-5510.

// pipelineRoot is the only directory the data readers below will serve from.
const pipelineRoot = "/srv/data"

// knownJobs maps a job name to the absolute executable that runs it. The
// pipeline scheduler picks a key; nothing in a request names a binary.
var knownJobs = map[string]string{
	"rollup":  "/usr/local/bin/pipeline-rollup",
	"compact": "/usr/local/bin/pipeline-compact",
	"verify":  "/usr/local/bin/pipeline-verify",
}

// benign: constant argument vector, no shell
func packConst() ([]byte, error) {
	return exec.Command("tar", "czf", "/backups/pipeline.tgz", "/var/pipeline").Output()
}

// benign: the job name is resolved through the table above, so the executable
// is always one this file names and the argument is fixed
func runKnownJob(name string) error {
	path, ok := knownJobs[name]
	if !ok {
		return os.ErrNotExist
	}
	return exec.Command(path, "--once").Run()
}

// benign: correct containment via Clean + prefix
func safeRead(name string) ([]byte, error) {
	base := "/srv/data"
	full := filepath.Join(base, filepath.Clean("/"+name))
	if !strings.HasPrefix(full, base) {
		return nil, os.ErrPermission
	}
	return os.ReadFile(full)
}

// benign: lists what safeRead can serve, skipping dotfiles and directories
func listData() ([]string, error) {
	entries, err := os.ReadDir(pipelineRoot)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// benign: exact host match after parsing
func validateHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Host == "cdn.slopshop.io"
}

// benign: scheme is pinned alongside the host, so a downgrade to plaintext is
// refused even when the host itself is the expected one
func validateEndpoint(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Scheme == "https" && u.Hostname() == "cdn.slopshop.io"
}

func runJob(w http.ResponseWriter, r *http.Request) {
	parts := strings.Fields(r.URL.Query().Get("job"))
	if len(parts) == 0 {
		return
	}
	exec.Command(parts[0], parts[1:]...).Run()
}

// benign: the request names a job key, and the executable comes from the map
func runNamedJob(w http.ResponseWriter, r *http.Request) {
	if err := runKnownJob(r.URL.Query().Get("job")); err != nil {
		http.Error(w, "unknown job", http.StatusBadRequest)
		return
	}
	w.Write([]byte("started"))
}

func readData(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("f")
	clean := filepath.Clean(name)
	_ = clean
	data, err := os.ReadFile("/srv/data/" + name)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Write(data)
}

// benign: the cleaned value is the one that gets used, and the result is
// checked for containment before the read happens
func readDataContained(w http.ResponseWriter, r *http.Request) {
	data, err := safeRead(r.URL.Query().Get("f"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Write(data)
}
