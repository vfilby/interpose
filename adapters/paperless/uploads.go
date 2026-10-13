package paperless

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Uploads remembers which documents each agent added, in uploads.json in the adapter directory. An agent may
// change the metadata of those documents (title, correspondent, type, tags) without a lease: it filed them, so
// fixing how they are filed is part of the same job. Nothing else in the archive is writable through the gateway.
type Uploads struct {
	path string

	mu   sync.Mutex
	docs map[string]map[int]time.Time // agent -> document id -> when it was consumed
}

// OpenUploads loads path (created when missing).
func OpenUploads(path string) (*Uploads, error) {
	u := &Uploads{path: path, docs: map[string]map[int]time.Time{}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return u, nil
	case err != nil:
		return nil, err
	}
	var raw map[string]map[string]time.Time
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	for agent, m := range raw {
		u.docs[agent] = map[int]time.Time{}
		for id, at := range m {
			if n, err := strconv.Atoi(id); err == nil && n > 0 {
				u.docs[agent][n] = at
			}
		}
	}
	return u, nil
}

func (u *Uploads) save() {
	if u.path == "" {
		return
	}
	raw := map[string]map[string]time.Time{}
	for agent, m := range u.docs {
		raw[agent] = map[string]time.Time{}
		for id, at := range m {
			raw[agent][strconv.Itoa(id)] = at
		}
	}
	b, err := json.MarshalIndent(raw, "", " ")
	if err != nil {
		return
	}
	tmp := u.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, u.path)
	}
}

// Add records that agent's upload became document id.
func (u *Uploads) Add(agent string, id int, at time.Time) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.docs[agent] == nil {
		u.docs[agent] = map[int]time.Time{}
	}
	u.docs[agent][id] = at
	u.save()
}

// Owns reports whether agent uploaded document id.
func (u *Uploads) Owns(agent string, id int) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	_, ok := u.docs[agent][id]
	return ok
}

// List is agent's uploads, newest first.
func (u *Uploads) List(agent string) []int {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]int, 0, len(u.docs[agent]))
	for id := range u.docs[agent] {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return u.docs[agent][out[i]].After(u.docs[agent][out[j]]) })
	return out
}
