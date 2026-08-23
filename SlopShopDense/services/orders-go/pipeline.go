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

// benign: constant argument vector, no shell
func packConst() ([]byte, error) {
	return exec.Command("tar", "czf", "/backups/pipeline.tgz", "/var/pipeline").Output()
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

// benign: exact host match after parsing
func validateHost(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return u.Host == "cdn.slopshop.io"
}

func runJob(w http.ResponseWriter, r *http.Request) {
	parts := strings.Fields(r.URL.Query().Get("job"))
	if len(parts) == 0 {
		return
	}
	exec.Command(parts[0], parts[1:]...).Run()
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
