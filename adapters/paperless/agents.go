package paperless

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Agents is who may talk to the gateway: a name per agent and the SHA-256 of its bearer token, in agents.json in
// the adapter directory. The token itself is printed once, when the agent is added, and goes into the agent's own
// credential store; the gateway keeps only the hash.
type Agents struct {
	path string

	mu      sync.Mutex
	entries map[string]agentEntry
}

type agentEntry struct {
	Hash    string    `json:"sha256"`
	Created time.Time `json:"created"`
}

var agentName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// ErrAgentName: not a usable agent name.
var ErrAgentName = errors.New("agent name: lowercase letters, digits, - and _, up to 32 characters")

// LoadAgents reads path (missing: no agents yet).
func LoadAgents(path string) (*Agents, error) {
	a := &Agents{path: path, entries: map[string]agentEntry{}}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return a, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(b, &a.entries); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return a, nil
}

func (a *Agents) save() error {
	b, err := json.MarshalIndent(a.entries, "", " ")
	if err != nil {
		return err
	}
	tmp := a.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.path)
}

func hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// Add creates (or replaces) name's token and returns the token: the only time it is visible.
func (a *Agents) Add(name string) (string, error) {
	if !agentName.MatchString(name) {
		return "", ErrAgentName
	}
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	tok := "ppg_" + hex.EncodeToString(b[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries[name] = agentEntry{Hash: hash(tok), Created: time.Now().UTC().Truncate(time.Second)}
	if err := a.save(); err != nil {
		return "", err
	}
	return tok, nil
}

// Remove forgets name.
func (a *Agents) Remove(name string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.entries[name]; !ok {
		return fmt.Errorf("no agent %q", name)
	}
	delete(a.entries, name)
	return a.save()
}

// Names lists the agents, sorted.
func (a *Agents) Names() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, 0, len(a.entries))
	for n := range a.entries {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the agent a bearer token belongs to. ok false: no agent has it.
func (a *Agents) Lookup(token string) (string, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	h := []byte(hash(token))
	a.mu.Lock()
	defer a.mu.Unlock()
	found := ""
	for name, e := range a.entries { // every entry is compared: the time taken does not say which one matched
		if subtle.ConstantTimeCompare(h, []byte(e.Hash)) == 1 {
			found = name
		}
	}
	return found, found != ""
}
