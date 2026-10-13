package paperless

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/internal/protocol"
)

// human is a duration as a person reads it: 45m, 2h, 1h30m.
func human(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	h, m := int(d.Hours()), int(d.Minutes())%60
	switch {
	case h == 0:
		return fmt.Sprintf("%dm", m)
	case m == 0:
		return fmt.Sprintf("%dh", h)
	}
	return fmt.Sprintf("%dh%dm", h, m)
}

// Kind is the record kind of a read lease.
const Kind = "paperless.read"

// MaxReason is how much of an agent's reason reaches the record (and so the adapter's state, audit log and the
// phone), in bytes.
const MaxReason = 1024

// Source turns pending leases into records; approve grants the lease, deny refuses it.
type Source struct {
	Store *Store
	Log   *slog.Logger // nil: slog.Default()
}

func (s *Source) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Source) Pending(context.Context) ([]adapter.Item, error) {
	var out []adapter.Item
	for _, l := range s.Store.Pending() {
		out = append(out, item(l))
	}
	return out, nil
}

func (s *Source) Current(_ context.Context, key string) (adapter.Item, bool, error) {
	l, ok := s.Store.Get(key)
	if !ok || l.Status != StatusPending {
		return adapter.Item{}, false, nil
	}
	return item(l), true, nil
}

func (s *Source) Approve(_ context.Context, key string) error {
	if err := s.Store.Approve(key); err != nil {
		return adapter.ErrGone
	}
	l, _ := s.Store.Get(key)
	s.log().Info("lease granted", "lease", key, "agent", l.Agent, "scope", l.Scope.Summary(), "until", l.ExpiresAt)
	return nil
}

func (s *Source) Deny(_ context.Context, key, reason string) error {
	if err := s.Store.Deny(key, reason); err != nil {
		return adapter.ErrGone
	}
	l, _ := s.Store.Get(key)
	s.log().Info("lease denied", "lease", key, "agent", l.Agent, "reason", reason)
	return nil
}

// item describes a lease request from the store's own state: the agent's name, the scope as resolved when it asked,
// the duration and the budget are the facts; its reason is quoted as its own claim.
func item(l Lease) adapter.Item {
	it := adapter.Item{
		Key:       l.ID,
		Kind:      Kind,
		Shape:     protocol.ShapeLease,
		Risk:      protocol.RiskNormal,
		Title:     fmt.Sprintf("%s wants to read Paperless: %s", l.Agent, l.Scope.Summary()),
		Requester: l.Agent,
		Facts:     []protocol.Fact{{Label: "Agent", Value: l.Agent}},
		Reason:    protocol.CleanText(l.Reason, MaxReason),
		Lease:     &protocol.Lease{DurationS: l.DurationS, Scope: l.Scope.Summary(), MaxUses: l.MaxDocuments},
	}
	if l.Scope.Empty() {
		it.Risk = protocol.RiskElevated
		it.Facts = append(it.Facts, protocol.Fact{Label: "Scope", Value: "every document", Level: "danger"})
	}
	for _, line := range l.Scope.Describe() {
		label, value, _ := strings.Cut(line, ": ")
		it.Facts = append(it.Facts, protocol.Fact{Label: label, Value: value})
	}
	it.Facts = append(it.Facts, protocol.Fact{Label: "Duration", Value: human(l.Duration())})
	budget := protocol.Fact{Label: "Documents", Value: fmt.Sprintf("up to %d", l.MaxDocuments)}
	if l.MaxDocuments == 0 {
		budget.Value, budget.Level = "unlimited", "warn"
	}
	it.Facts = append(it.Facts, budget)
	return it
}
