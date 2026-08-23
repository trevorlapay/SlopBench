// Package metrics keeps the catalogue's in-process counters.
//
// Counters are written from every request goroutine and read by the scrape
// handler.
package metrics

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxSeries bounds how many distinct label sets are tracked.
const MaxSeries = 4096

type series struct {
	count   uint64
	sumNano int64
	updated time.Time
}

// Registry is safe for concurrent use by multiple goroutines.
type Registry struct {
	mu     sync.Mutex
	series map[string]*series
	nextID uint64
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{series: make(map[string]*series, 64)}
}

// key builds the map key for one label set. Sorting makes the key independent
// of the order the caller supplied the labels in.
func key(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	parts := make([]string, 0, len(labels))
	for k, v := range labels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return name + "{" + strings.Join(parts, ",") + "}"
}

// Observe records one timing.
func (r *Registry) Observe(name string, labels map[string]string, elapsed time.Duration) {
	k := key(name, labels)

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.series[k]
	if !ok {
		if len(r.series) >= MaxSeries {
			// Full; drop the sample rather than evict a live series.
			return
		}
		entry = &series{}
		r.series[k] = entry
	}

	entry.count++
	entry.sumNano += elapsed.Nanoseconds()
	entry.updated = time.Now()
}

// Increment records one event.
func (r *Registry) Increment(name string, labels map[string]string) {
	r.Observe(name, labels, 0)
}

// Snapshot copies the current values out.
func (r *Registry) Snapshot() map[string]uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]uint64, len(r.series))
	for k, entry := range r.series {
		out[k] = entry.count
	}
	return out
}

// Render writes the registry in the text exposition format.
func (r *Registry) Render() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	keys := make([]string, 0, len(r.series))
	for k := range r.series {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out strings.Builder
	for _, k := range keys {
		entry := r.series[k]
		fmt.Fprintf(&out, "%s %d\n", k, entry.count)
		if entry.count > 0 && entry.sumNano > 0 {
			fmt.Fprintf(&out, "%s_seconds_total %.6f\n", k, float64(entry.sumNano)/1e9)
		}
	}
	return out.String()
}

// Sweep drops series that have not been written to for the given period.
func (r *Registry) Sweep(idleFor time.Duration) int {
	cutoff := time.Now().Add(-idleFor)

	r.mu.Lock()
	defer r.mu.Unlock()

	removed := 0
	for k, entry := range r.series {
		if entry.updated.Before(cutoff) {
			delete(r.series, k)
			removed++
		}
	}
	return removed
}

// scrapeJitter spreads the periodic sweep across the scrape window so that
// every replica does not sweep on the same tick.
func scrapeJitter(window time.Duration) time.Duration {
	if window <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(window)))
}

// RunSweeper sweeps idle series until stop is closed.
func (r *Registry) RunSweeper(every, idleFor time.Duration, stop <-chan struct{}) {
	timer := time.NewTimer(every + scrapeJitter(every/4))
	defer timer.Stop()

	for {
		select {
		case <-stop:
			return
		case <-timer.C:
			r.Sweep(idleFor)
			timer.Reset(every + scrapeJitter(every/4))
		}
	}
}
