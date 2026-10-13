// Package paperless is the Source of the Paperless adapter and the gateway agents use. An agent may add documents
// without asking anyone; to read it asks for a lease (a scope, a duration and a document budget), a person grants it
// on a phone, and the gateway enforces it on every read. Agents hold a token for the gateway only; the Paperless token
// stays here.
//
// A lease's life:
//
//	pending    asked for by an agent; the adapter core has sent (or is sending) the record to the phones
//	approved   granted; reads inside its scope work until it expires or its document budget is spent
//	denied     refused on a phone, or unanswered until the record expired (the core fails closed)
//	expired    an approved lease past its duration
package paperless

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusDenied   = "denied"
	StatusExpired  = "expired"
)

// Scope is what a lease lets an agent see. Empty: every document the adapter's Paperless user can see.
type Scope struct {
	// Names, as the agent asked and the person saw them.
	Correspondent string   `json:"correspondent,omitempty"`
	DocumentType  string   `json:"document_type,omitempty"`
	Tags          []string `json:"tags,omitempty"` // all of them
	Query         string   `json:"query,omitempty"`
	Documents     []int    `json:"documents,omitempty"`
	// Ids resolved when the lease was asked for: what is enforced. A rename in Paperless changes nothing.
	CorrespondentID int   `json:"correspondent_id,omitempty"`
	DocumentTypeID  int   `json:"document_type_id,omitempty"`
	TagIDs          []int `json:"tag_ids,omitempty"`
}

// Empty reports whether the scope limits nothing.
func (s Scope) Empty() bool {
	return s.CorrespondentID == 0 && s.DocumentTypeID == 0 && len(s.TagIDs) == 0 && s.Query == "" && len(s.Documents) == 0
}

// Filter is the scope as Paperless list parameters. Query is left out: it combines with the agent's own search.
func (s Scope) Filter() url.Values {
	q := url.Values{}
	if s.CorrespondentID != 0 {
		q.Set("correspondent__id", strconv.Itoa(s.CorrespondentID))
	}
	if s.DocumentTypeID != 0 {
		q.Set("document_type__id", strconv.Itoa(s.DocumentTypeID))
	}
	if len(s.TagIDs) > 0 {
		q.Set("tags__id__all", ints(s.TagIDs))
	}
	if len(s.Documents) > 0 {
		q.Set("id__in", ints(s.Documents))
	}
	return q
}

// Describe is the scope in words, one line per limit, for the phone and the audit log.
func (s Scope) Describe() []string {
	var out []string
	if s.Correspondent != "" {
		out = append(out, "Correspondent: "+s.Correspondent)
	}
	if s.DocumentType != "" {
		out = append(out, "Document type: "+s.DocumentType)
	}
	if len(s.Tags) > 0 {
		out = append(out, "Tags: "+strings.Join(s.Tags, ", "))
	}
	if s.Query != "" {
		out = append(out, "Search: "+s.Query)
	}
	if len(s.Documents) > 0 {
		out = append(out, "Documents: #"+strings.Join(strings.Split(ints(s.Documents), ","), ", #"))
	}
	return out
}

// Summary is the scope on one line.
func (s Scope) Summary() string {
	if s.Empty() {
		return "every document"
	}
	return strings.Join(s.Describe(), "; ")
}

func ints(v []int) string {
	parts := make([]string, len(v))
	for i, n := range v {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ",")
}

// Lease is one read lease, asked for by one agent.
type Lease struct {
	ID           string    `json:"id"`
	Agent        string    `json:"agent"`
	Scope        Scope     `json:"scope"`
	DurationS    int64     `json:"duration_s"`
	MaxDocuments int       `json:"max_documents"` // 0: unlimited
	Reason       string    `json:"reason"`
	Status       string    `json:"status"`
	Created      time.Time `json:"created"`
	Decided      time.Time `json:"decided,omitempty"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"` // approved: when the lease ends
	DenyReason   string    `json:"deny_reason,omitempty"`
	Read         []int     `json:"read,omitempty"` // documents whose content or file was served, once each
}

// Duration is the lease's length.
func (l Lease) Duration() time.Duration { return time.Duration(l.DurationS) * time.Second }

// Store holds the leases, on disk between restarts.
type Store struct {
	path string
	now  func() time.Time

	mu      sync.Mutex
	leases  map[string]*Lease
	changed chan struct{} // closed and replaced on every change: waiters wake up
}

// OpenStore loads path (created when missing).
func OpenStore(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, leases: map[string]*Lease{}, changed: make(chan struct{})}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, err
	}
	var ls []*Lease
	if err := json.Unmarshal(b, &ls); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, l := range ls {
		s.leases[l.ID] = l
	}
	return s, nil
}

// keepFinished: how long a finished lease stays listed for its agent.
const keepFinished = 7 * 24 * time.Hour

func (s *Store) save() {
	now := s.now()
	ls := make([]*Lease, 0, len(s.leases))
	for id, l := range s.leases {
		if s.status(l, now) != StatusPending && s.status(l, now) != StatusApproved && now.Sub(latest(l)) > keepFinished {
			delete(s.leases, id)
			continue
		}
		ls = append(ls, l)
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].Created.Before(ls[j].Created) })
	close(s.changed)
	s.changed = make(chan struct{})
	if s.path == "" { // tests
		return
	}
	b, err := json.MarshalIndent(ls, "", " ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err == nil {
		_ = os.Rename(tmp, s.path)
	}
}

func latest(l *Lease) time.Time {
	t := l.Created
	for _, u := range []time.Time{l.Decided, l.ExpiresAt} {
		if u.After(t) {
			t = u
		}
	}
	return t
}

// status is the lease's state now: an approved lease past its end reads as expired.
func (s *Store) status(l *Lease, now time.Time) string {
	if l.Status == StatusApproved && !now.Before(l.ExpiresAt) {
		return StatusExpired
	}
	return l.Status
}

// view is a copy of l with its status as of now.
func (s *Store) view(l *Lease) Lease {
	v := *l
	v.Status = s.status(l, s.now())
	v.Read = slices.Clone(l.Read)
	v.Scope.Tags = slices.Clone(l.Scope.Tags)
	v.Scope.TagIDs = slices.Clone(l.Scope.TagIDs)
	v.Scope.Documents = slices.Clone(l.Scope.Documents)
	return v
}

func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

// Add files a new pending lease and returns it.
func (s *Store) Add(agent string, scope Scope, d time.Duration, maxDocs int, reason string) Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := &Lease{ID: newID(), Agent: agent, Scope: scope, DurationS: int64(d / time.Second), MaxDocuments: maxDocs,
		Reason: reason, Status: StatusPending, Created: s.now()}
	s.leases[l.ID] = l
	s.save()
	return s.view(l)
}

// Get returns one lease. ok false: no such lease.
func (s *Store) Get(id string) (Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[id]
	if !ok {
		return Lease{}, false
	}
	return s.view(l), true
}

// Pending lists the leases waiting for a person, oldest first.
func (s *Store) Pending() []Lease {
	return s.list(func(l Lease) bool { return l.Status == StatusPending })
}

// ByAgent lists one agent's leases, oldest first.
func (s *Store) ByAgent(agent string) []Lease {
	return s.list(func(l Lease) bool { return l.Agent == agent })
}

func (s *Store) list(keep func(Lease) bool) []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Lease
	for _, l := range s.leases {
		if v := s.view(l); keep(v) {
			out = append(out, v)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// ErrNotPending: the lease is not waiting for a decision.
var ErrNotPending = errors.New("lease is not pending")

// Approve grants a pending lease from now.
func (s *Store) Approve(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[id]
	if !ok || l.Status != StatusPending {
		return ErrNotPending
	}
	now := s.now()
	l.Status, l.Decided, l.ExpiresAt = StatusApproved, now, now.Add(l.Duration())
	s.save()
	return nil
}

// Deny refuses a pending lease.
func (s *Store) Deny(id, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[id]
	if !ok || l.Status != StatusPending {
		return ErrNotPending
	}
	l.Status, l.Decided, l.DenyReason = StatusDenied, s.now(), reason
	s.save()
	return nil
}

// Errors a read can meet.
var (
	ErrNoLease     = errors.New("no such lease")
	ErrNotApproved = errors.New("lease is not approved")
	ErrLeaseEnded  = errors.New("lease has expired")
	ErrBudgetSpent = errors.New("lease has read its maximum number of documents")
	ErrNotYours    = errors.New("lease belongs to another agent")
)

// Use returns the lease if agent may read with it now. A read of document doc (0: a search) is charged to its
// budget: a document already read is free, a new one past the budget is refused.
func (s *Store) Use(agent, id string, doc int) (Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[id]
	if !ok {
		return Lease{}, ErrNoLease
	}
	if l.Agent != agent {
		return Lease{}, ErrNotYours
	}
	switch s.status(l, s.now()) {
	case StatusApproved:
	case StatusExpired:
		return Lease{}, ErrLeaseEnded
	default:
		return Lease{}, ErrNotApproved
	}
	if doc > 0 && !slices.Contains(l.Read, doc) {
		if l.MaxDocuments > 0 && len(l.Read) >= l.MaxDocuments {
			return Lease{}, ErrBudgetSpent
		}
		l.Read = append(l.Read, doc)
		s.save()
	}
	return s.view(l), nil
}

// Wait blocks until lease id leaves status was, or ctx ends. It returns the lease as it is then.
func (s *Store) Wait(ctx context.Context, id, was string) (Lease, bool) {
	for {
		s.mu.Lock()
		l, ok := s.leases[id]
		var v Lease
		if ok {
			v = s.view(l)
		}
		ch := s.changed
		s.mu.Unlock()
		if !ok || v.Status != was {
			return v, ok
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return v, ok
		case <-time.After(time.Second): // an approved lease expires without a change event
		}
	}
}
