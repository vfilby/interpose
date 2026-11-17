package e2e_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/internal/protocol"
)

// fakeDir stands in for an LDAP directory: users by uid with their account attribute, groups by name with member
// uids. Nothing here is signed or verified; it is exactly as trustworthy as the directory it stands for.
type fakeDir struct {
	users  map[string]string
	groups map[string][]string
	err    error
}

func (d *fakeDir) User(_ context.Context, uid string) (adapter.Entry, bool, error) {
	if d.err != nil {
		return adapter.Entry{}, false, d.err
	}
	a, ok := d.users[uid]
	return adapter.Entry{UID: uid, Account: a}, ok, nil
}

func (d *fakeDir) Group(_ context.Context, g string) ([]adapter.Entry, bool, error) {
	if d.err != nil {
		return nil, false, d.err
	}
	uids, ok := d.groups[g]
	if !ok {
		return nil, false, nil
	}
	var out []adapter.Entry
	for _, u := range uids {
		if a, ok := d.users[u]; ok {
			out = append(out, adapter.Entry{UID: u, Account: a})
		}
	}
	return out, true, nil
}

func ldapSources(t *testing.T, s string) []adapter.TrustSource {
	t.Helper()
	srcs, err := adapter.ParseTrustSources(s)
	if err != nil {
		t.Fatal(err)
	}
	return srcs
}

// ldapWorld is a world whose adapter trusts nobody locally: only the members of group "approvers" in d, where vince
// has his account on his entry.
func ldapWorld(t *testing.T) (*world, *fakeDir) {
	d := &fakeDir{groups: map[string][]string{"approvers": {"vince"}}}
	w := newWorldWith(t, func(w *world) adapter.TrustOptions {
		d.users = map[string]string{"vince": w.account}
		return adapter.TrustOptions{Sources: ldapSources(t, "ldap-group:approvers"), Directory: d, Refresh: time.Minute, Stale: 15 * time.Minute}
	})
	return w, d
}

// A member of the group, with their account on their entry, is asked and can approve; the outcome names the source.
// Who is trusted, and from where, is in the audit log.
func TestLDAPGroupMemberApproves(t *testing.T) {
	w, _ := ldapWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "via the group")
	if n := len(w.pending(w.strHub)); n != 0 {
		t.Fatalf("a device of a user not in the group got %d boxes", n)
	}
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("not approved at the service")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeApproved || a.Detail != "approved by vince on phone (ldap-group:approvers)" {
		t.Fatalf("ack %+v", a)
	}
	evs, _ := w.auditEvents()
	added := 0
	for _, e := range evs {
		if e.Event == "trust-added" && e.Requester == "vince" && e.Detail == "account "+w.account+" via ldap-group:approvers" {
			added++
		}
	}
	if added != 1 {
		t.Fatalf("%d trust-added entries for vince", added)
	}
}

// Leaving the group between being asked and answering: the decision is refused, since the directory is asked live,
// and the request stays pending for whoever is still trusted. The next refresh stops asking them at all.
func TestLDAPLeftGroupBeforeDeciding(t *testing.T) {
	w, d := ldapWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "left the group")
	d.groups["approvers"] = nil
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("acted on a decision by a user who left the group")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected || !strings.Contains(a.Detail, "vince is no longer a member") {
		t.Fatalf("ack %+v", a)
	}

	w.advance(2 * time.Minute)
	w.tick()
	evs, _ := w.auditEvents()
	if count(evs, "trust-removed") != 1 {
		t.Fatalf("trust-removed entries: %d", count(evs, "trust-removed"))
	}
	w.src.Add(adapter.Item{Requester: "claude", Title: "nobody to ask"})
	w.tick()
	for _, r := range w.pending(w.phoneHub) {
		if o, err := w.phone.Read(r.Box, w.adPub); err == nil && o.Record.Title == "nobody to ask" {
			t.Fatal("a request was sealed for a device of a user no longer trusted")
		}
	}

	// Back in the group: asked again, and the saved roster is reused (no rollback window).
	d.groups["approvers"] = []string{"vince"}
	w.advance(2 * time.Minute)
	it2, o2 := w.openOne(w.phone, w.phoneHub, "back in the group")
	w.decide(w.phone, o2, protocol.Deny)
	if w.outcome(it2.Key) != "resolved" {
		t.Fatal("not denied at the service")
	}
}

// With the directory unreachable, decisions by its users are refused (fail closed); local users are unaffected.
func TestLDAPDirectoryDownRefusesDecisions(t *testing.T) {
	w, d := ldapWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "directory down")
	d.err = errors.New("connection refused")
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("acted while the directory could not be asked")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected || !strings.Contains(a.Detail, "directory check failed: connection refused") {
		t.Fatalf("ack %+v", a)
	}
	// Still asked, on the last good pins, until stale.
	w.advance(2 * time.Minute)
	w.tick()
	if len(w.pending(w.phoneHub)) == 0 {
		t.Fatal("request withdrawn during a short outage")
	}
	// Once the directory answers, the same decision form goes through.
	d.err = nil
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("not approved once the directory was back")
	}
}

// An entry whose account does not match the user's roster pins nothing usable: the chain from the hub does not verify
// against it, so none of that user's devices is asked or believed. A stranger's phone put on the group with vince's
// fingerprint gets nothing either: the chain under kim's name hashes differently.
func TestLDAPWrongAccountTrustsNobody(t *testing.T) {
	d := &fakeDir{groups: map[string][]string{"approvers": {"vince", "kim"}}}
	w := newWorldWith(t, func(w *world) adapter.TrustOptions {
		d.users = map[string]string{"vince": "0000-1111-2222-3333-4444-5555-6666-7777", "kim": w.account}
		return adapter.TrustOptions{Sources: ldapSources(t, "ldap-group:approvers"), Directory: d}
	})
	w.src.Add(adapter.Item{Requester: "claude", Title: "wrong accounts"})
	w.tick()
	if n := len(w.pending(w.phoneHub)) + len(w.pending(w.strHub)); n != 0 {
		t.Fatalf("%d boxes sealed for users whose accounts do not match", n)
	}
	pins, heads := w.ad.Trust().Pins()
	if len(pins) != 2 || len(heads) != 0 {
		t.Fatalf("pins %+v heads %+v", pins, heads)
	}
}

// Local pins and LDAP sources work side by side: vince locally, kim through the group, each deciding for themselves.
func TestLDAPAndLocalTogether(t *testing.T) {
	d := &fakeDir{groups: map[string][]string{"approvers": {"kim"}}}
	w := newWorldWith(t, func(w *world) adapter.TrustOptions {
		if err := adapter.TrustAddUser(w.dir, "vince", w.account); err != nil {
			t.Fatal(err)
		}
		kim, _ := w.store.Chain("kim")
		h, err := protocol.VerifyChain(kim, "kim", "")
		if err != nil {
			t.Fatal(err)
		}
		d.users = map[string]string{"kim": h.Account}
		return adapter.TrustOptions{Sources: ldapSources(t, "local,ldap-group:approvers"), Directory: d}
	})
	it, o := w.openOne(w.phone, w.phoneHub, "both")
	w.decide(w.phone, o, protocol.Deny)
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeDenied || a.Detail != "denied by vince on phone" {
		t.Fatalf("local user: ack %+v", a)
	}
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("not denied at the service")
	}

	it, o = w.openOne(w.stranger, w.strHub, "kim's turn")
	e, _ := w.stranger.Decide(o, "kim", protocol.Approve, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("kim's approval did not act")
	}
	acks, err := w.strHub.Acks(w.ctx, 0)
	if err != nil || len(acks) == 0 {
		t.Fatalf("acks %v %v", acks, err)
	}
}
