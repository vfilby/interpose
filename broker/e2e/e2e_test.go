package e2e_test

import (
	"context"
	"crypto/ed25519"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapter/demo"
	"github.com/vfilby/interpose/broker/internal/hub"
	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// world is a hub over real HTTP and one demo adapter that trusts user "vince", whose first device is "phone".
// "stranger" is the first device of user "kim", whom the adapter does not trust.
type world struct {
	t       *testing.T
	ctx     context.Context
	dir     string
	store   *hub.Store
	src     *demo.Source
	ad      *adapter.Adapter
	adHub   *adapter.HubClient
	adPub   ed25519.PublicKey
	srvURL  string
	account string
	audit   string // the adapter's audit.jsonl

	phone    *softdevice.Device
	phoneHub *softdevice.Client
	stranger *softdevice.Device
	strHub   *softdevice.Client

	mu  sync.Mutex
	now time.Time
}

func (w *world) clock() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

func (w *world) advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

// enroll makes a device and enrolls it with a code for user/mode.
func (w *world) enroll(name, user, mode string) (*softdevice.Device, *softdevice.Client, softdevice.EnrollResult) {
	w.t.Helper()
	d, _ := softdevice.New(name)
	card, _ := d.Card(w.now)
	code, _, err := w.store.NewEnrollCode(time.Now(), user, mode)
	if err != nil {
		w.t.Fatal(err)
	}
	var genesis *protocol.Envelope
	if mode == hub.ModeNew {
		g, _ := d.Genesis(user, w.now)
		genesis = &g
	}
	c := &softdevice.Client{Base: w.srvURL}
	res, err := c.Enroll(w.ctx, code, card, genesis)
	if err != nil {
		w.t.Fatal(err)
	}
	return d, c, res
}

func newWorld(t *testing.T) *world {
	t.Helper()
	return newWorldWith(t, nil)
}

// newWorldWith lets a test choose the adapter's trust sources. trust is called once the accounts exist (w.account is
// vince's); nil pins vince locally.
func newWorldWith(t *testing.T, trust func(w *world) adapter.TrustOptions) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, ctx: context.Background(), dir: dir, now: time.Now()}
	st, err := hub.Open(filepath.Join(dir, "hub.json"))
	if err != nil {
		t.Fatal(err)
	}
	w.store = st
	srv := httptest.NewServer((&hub.API{Store: st, MaxWait: 200 * time.Millisecond}).Handler())
	t.Cleanup(srv.Close)
	w.srvURL = srv.URL

	pub, key, _ := ed25519.GenerateKey(nil)
	w.adPub = pub
	tok, err := st.AddAdapter("demo", protocol.B64(pub), w.now)
	if err != nil {
		t.Fatal(err)
	}
	w.adHub = &adapter.HubClient{Base: srv.URL, Token: tok}

	w.phone, w.phoneHub, _ = w.enroll("phone", "vince", hub.ModeNew)
	w.stranger, w.strHub, _ = w.enroll("stranger", "kim", hub.ModeNew)
	chain, _ := st.Chain("vince")
	h, err := protocol.VerifyChain(chain, "vince", "")
	if err != nil {
		t.Fatal(err)
	}
	w.account = h.Account // what the phone shows; the admin types it into trust add-user

	opts := adapter.TrustOptions{Now: w.clock}
	if trust == nil {
		if err := adapter.TrustAddUser(dir, "vince", w.account); err != nil {
			t.Fatal(err)
		}
	} else {
		opts = trust(w)
		opts.Now = w.clock
	}
	tr, err := adapter.NewTrust(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	w.src = demo.New()
	w.audit = filepath.Join(dir, "audit.jsonl")
	al, err := audit.Open(w.audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	w.ad, err = adapter.New(adapter.Config{ID: "demo", Key: key, StateFile: filepath.Join(dir, "adapter.json"),
		TTL: 15 * time.Minute, Poll: time.Hour, Now: w.clock}, w.src, w.adHub, tr, al,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *world) tick() {
	w.t.Helper()
	if err := w.ad.Tick(w.ctx); err != nil {
		w.t.Fatal(err)
	}
}

func (w *world) pending(c *softdevice.Client) []softdevice.HubRequest {
	w.t.Helper()
	rs, err := c.Requests(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	return rs
}

func (w *world) head() protocol.Head {
	w.t.Helper()
	chain, err := w.phoneHub.Roster(w.ctx)
	if err != nil {
		w.t.Fatal(err)
	}
	h, err := protocol.VerifyChain(chain, "vince", w.account)
	if err != nil {
		w.t.Fatal(err)
	}
	return h
}

func (w *world) decide(d *softdevice.Device, o softdevice.Opened, dec string) {
	w.t.Helper()
	e, _ := d.Decide(o, "vince", dec, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
}

func (w *world) lastAck(id string) protocol.Ack {
	w.t.Helper()
	acks, err := w.phoneHub.Acks(w.ctx, 0)
	if err != nil {
		w.t.Fatal(err)
	}
	var out protocol.Ack
	found := false
	for _, a := range acks {
		if a.RequestID != id {
			continue
		}
		ack, err := softdevice.ReadAck(a.Ack, w.adPub)
		if err != nil {
			w.t.Fatalf("ack does not verify: %v", err)
		}
		out, found = ack, true
	}
	if !found {
		w.t.Fatalf("no ack for %s", id)
	}
	return out
}

func (w *world) outcome(key string) string {
	_, ok, _ := w.src.Current(w.ctx, key)
	if ok {
		return "pending"
	}
	return "resolved"
}

// openOne adds a demo request, publishes it, and opens it on d.
func (w *world) openOne(d *softdevice.Device, c *softdevice.Client, title string) (adapter.Item, softdevice.Opened) {
	w.t.Helper()
	it := w.src.Add(adapter.Item{Requester: "claude", Title: title})
	w.tick()
	for _, r := range w.pending(c) {
		o, err := d.Read(r.Box, w.adPub)
		if err == nil && o.Record.Title == title {
			return it, o
		}
	}
	w.t.Fatalf("%q not delivered", title)
	return it, softdevice.Opened{}
}

func TestApproveEndToEnd(t *testing.T) {
	w := newWorld(t)
	it := w.src.Add(adapter.Item{Requester: "claude", Title: "claude wants RW on db-01", Risk: protocol.RiskElevated,
		Reason: "fix the backups", Facts: []protocol.Fact{{Label: "Host", Value: "db-01"}}})
	w.tick()

	if n := len(w.pending(w.strHub)); n != 0 {
		t.Fatalf("a device of a user the adapter does not trust got %d boxes", n)
	}
	rs := w.pending(w.phoneHub)
	if len(rs) != 1 {
		t.Fatalf("phone sees %d requests", len(rs))
	}
	o, err := w.phone.Read(rs[0].Box, w.adPub)
	if err != nil {
		t.Fatal(err)
	}
	if o.Record.Title != it.Title || o.Record.Reason != "fix the backups" {
		t.Fatalf("record %+v", o.Record)
	}
	dec, _ := w.phone.Decide(o, "vince", protocol.Approve, w.clock())
	if err := w.phoneHub.Decide(w.ctx, "demo", o.Record.ID, dec); err != nil {
		t.Fatal(err)
	}
	ds, err := w.adHub.Decisions(w.ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		w.ad.Handle(w.ctx, d)
	}

	if w.outcome(it.Key) != "resolved" {
		t.Fatal("the service was not acted on")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeApproved || !strings.Contains(a.Detail, "vince") {
		t.Fatalf("ack %+v", a)
	}
	if n := len(w.pending(w.phoneHub)); n != 0 {
		t.Fatalf("resolved request still offered (%d)", n)
	}
	// Replaying the same decision does nothing: the record is gone, its nonce with it.
	if err := w.phoneHub.Decide(w.ctx, "demo", o.Record.ID, dec); err == nil {
		t.Fatal("hub accepted a decision for a resolved request")
	}
}

// The hub (or anything that gets onto it) forges approvals: none of them may act.
func TestForgedDecisionsDoNothing(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "helper wants ADMIN on web-02")

	// 1. A device of another user (enrolled at the hub, not trusted by the adapter), signing the real record.
	strDec, _ := w.stranger.Decide(o, "kim", protocol.Approve, w.clock())
	// 2. A deny signed by the phone, with the payload edited to "approve".
	deny, _ := w.phone.Decide(o, "vince", protocol.Deny, w.clock())
	p, _ := deny.PayloadBytes()
	deny.Payload = protocol.B64([]byte(strings.Replace(string(p), `"deny"`, `"approve"`, 1)))
	// 3. A genuine phone approval of a different record.
	_, oo := w.openOne(w.phone, w.phoneHub, "harmless")
	swapped, _ := w.phone.Decide(oo, "vince", protocol.Approve, w.clock())

	for _, d := range []protocol.Envelope{strDec, deny, swapped} {
		w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: d.Kid, Decision: d})
	}
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a forged decision acted on the service")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected {
		t.Fatalf("want a rejected note, got %+v", a)
	}
	w.decide(w.phone, o, protocol.Deny) // the person can still decide
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeDenied {
		t.Fatalf("ack %+v", a)
	}
}

func TestChangedRequestIsResent(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "first wording")
	w.src.Mutate(it.Key, func(i *adapter.Item) { i.Title = "second wording" })
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("approved a request that changed after it was shown")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeExpired || !strings.Contains(a.Detail, "changed") {
		t.Fatalf("ack %+v", a)
	}
	w.tick()
	rs := w.pending(w.phoneHub)
	if len(rs) != 1 || rs[0].ID == o.Record.ID {
		t.Fatalf("want one fresh record, got %+v", rs)
	}
}

func TestUnansweredIsDenied(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	w.advance(16 * time.Minute)
	w.tick()
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("expired request not denied at the service")
	}
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeExpired {
		t.Fatalf("ack %+v", a)
	}
}

func TestStaleDecisionRejected(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	dec, _ := w.phone.Decide(o, "vince", protocol.Approve, w.clock())
	w.advance(6 * time.Minute) // held back by the transport for longer than the window
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: dec.Kid, Decision: dec})
	if w.outcome(it.Key) != "pending" {
		t.Fatal("acted on a stale decision")
	}
}

func TestUntrustedUserAtAdapterStopsDecisions(t *testing.T) {
	w := newWorld(t)
	it, o := w.openOne(w.phone, w.phoneHub, "x")
	time.Sleep(10 * time.Millisecond) // distinct mtime
	if err := adapter.TrustRemoveUser(w.dir, "vince"); err != nil {
		t.Fatal(err)
	}
	w.tick()
	w.decide(w.phone, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a device of a user the adapter no longer trusts acted")
	}
}

// A second phone joins vince: nothing reaches it until a phone already on the roster admits it.
func TestJoinApprovedOnExistingPhone(t *testing.T) {
	w := newWorld(t)
	phone2, hub2, res := w.enroll("phone 2", "vince", hub.ModeJoin)
	if res.Status != "pending" {
		t.Fatalf("join status %q", res.Status)
	}
	_, _ = w.openOne(w.phone, w.phoneHub, "before admission")
	if rs, err := hub2.Requests(w.ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a device waiting for approval was served requests: %d boxes, %v", len(rs), err)
	}
	if _, err := hub2.Roster(w.ctx); err != nil {
		t.Fatalf("a device waiting for approval cannot read its roster: %v", err)
	}

	// A device cannot admit itself: the hub refuses, and so would every adapter.
	self, _ := phone2.Admit(w.head(), mustCard(t, phone2), w.now)
	if err := hub2.PostRoster(w.ctx, self); err == nil {
		t.Fatal("hub accepted a self-admission")
	}

	joins, err := w.phoneHub.Joins(w.ctx)
	if err != nil || len(joins) != 1 || joins[0].DeviceID != phone2.ID() {
		t.Fatalf("joins %+v %v", joins, err)
	}
	next, _ := w.phone.Admit(w.head(), joins[0].Card, w.now)
	if err := w.phoneHub.PostRoster(w.ctx, next); err != nil {
		t.Fatal(err)
	}

	it, o := w.openOne(phone2, hub2, "after admission")
	w.decide(phone2, o, protocol.Approve)
	if w.outcome(it.Key) != "resolved" {
		t.Fatal("admitted phone could not approve")
	}
	if a := w.lastAck(o.Record.ID); !strings.Contains(a.Detail, "vince on phone 2") {
		t.Fatalf("ack %+v", a)
	}
}

// Phone 2 is removed by phone 1. Its decisions stop counting at the adapter, and the hub stops serving it.
func TestRemovedPhoneCannotDecide(t *testing.T) {
	w := newWorld(t)
	phone2, hub2 := w.admitSecond()
	it, o := w.openOne(phone2, hub2, "sealed to both")

	rm, _ := w.phone.Remove(w.head(), phone2.ID(), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, rm); err != nil {
		t.Fatal(err)
	}
	w.tick() // the adapter picks up the new roster
	w.decide(phone2, o, protocol.Approve)
	if w.outcome(it.Key) != "pending" {
		t.Fatal("a removed phone's decision acted")
	}
	if _, err := hub2.Requests(w.ctx); err == nil {
		t.Fatal("the hub still serves a removed phone")
	}
}

// The hub turns hostile after phone 2's removal: it serves the old roster, a forked one, or another account.
func TestHostileHubRosters(t *testing.T) {
	w := newWorld(t)
	phone2, _ := w.admitSecond()
	before, _ := w.store.Chain("vince") // v2: phone + phone 2
	h2 := w.head()
	rm, _ := w.phone.Remove(h2, phone2.ID(), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, rm); err != nil {
		t.Fatal(err)
	}
	w.tick() // adapter now at v3: phone only

	mallory, _ := softdevice.New("mallory")
	mCard := mustCard(t, mallory)
	forkV3, _ := phone2.Admit(h2, mCard, w.now) // phone 2 was still on v2, so it can sign an alternative v3
	hFork, err := protocol.Extend(h2, forkV3)
	if err != nil {
		t.Fatal(err)
	}
	forkV4, _ := mallory.Admit(hFork, mustCard(t, phone2), w.now)
	other, _ := mallory.Genesis("vince", w.now)

	for name, chain := range map[string][]protocol.Envelope{
		"rollback to v2":              before,
		"fork from v2 (v3', v4')":     append(append([]protocol.Envelope{}, before...), forkV3, forkV4),
		"another account named vince": {other},
	} {
		w.store.ForceChain("vince", chain)
		w.tick()
		_, o := w.openOne(w.phone, w.phoneHub, "after: "+name)
		for _, d := range []*softdevice.Device{phone2, mallory} {
			e, _ := d.Decide(o, "vince", protocol.Approve, w.clock())
			w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
		}
		if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected {
			t.Errorf("%s: a removed or injected device's decision was not rejected: %+v", name, a)
		}
		// And the record was sealed to the phone only.
		if n := len(w.pending(w.phoneHub)); n == 0 {
			t.Errorf("%s: the legitimate phone lost its requests", name)
		}
	}
}

// admitSecond enrolls "phone 2" for vince and admits it from the first phone.
func (w *world) admitSecond() (*softdevice.Device, *softdevice.Client) {
	w.t.Helper()
	phone2, hub2, _ := w.enroll("phone 2", "vince", hub.ModeJoin)
	next, _ := w.phone.Admit(w.head(), mustCard(w.t, phone2), w.now)
	if err := w.phoneHub.PostRoster(w.ctx, next); err != nil {
		w.t.Fatal(err)
	}
	w.tick()
	return phone2, hub2
}

func mustCard(t *testing.T, d *softdevice.Device) protocol.Envelope {
	t.Helper()
	c, err := d.Card(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A device on the rosters of two trusted users speaks for the user its decision names, and only for a user whose
// roster it is on.
func TestDecisionNamesItsUser(t *testing.T) {
	w := newWorld(t)
	// kim's stranger puts vince's phone on kim's roster too, and the adapter trusts kim as well.
	kim, _ := w.store.Chain("kim")
	h, err := protocol.VerifyChain(kim, "kim", "")
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := w.stranger.Admit(h, mustCard(t, w.phone), w.now)
	w.store.ForceChain("kim", append(kim, r2))
	if err := adapter.TrustAddUser(w.dir, "kim", h.Account); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct{ user, want string }{
		{"vince", "denied by vince on phone"},
		{"kim", "denied by kim on phone"},
	} {
		it, o := w.openOne(w.phone, w.phoneHub, "as "+c.user)
		e, _ := w.phone.Decide(o, c.user, protocol.Deny, w.clock())
		w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
		if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeDenied || a.Detail != c.want {
			t.Errorf("as %s: ack %+v, want %q", c.user, a, c.want)
		}
		if w.outcome(it.Key) != "resolved" {
			t.Errorf("as %s: not denied at the service", c.user)
		}
	}

	it, o := w.openOne(w.phone, w.phoneHub, "as a user whose roster the phone is not on")
	e, _ := w.phone.Decide(o, "lee", protocol.Approve, w.clock())
	w.ad.Handle(w.ctx, adapter.QueuedDecision{Adapter: "demo", RequestID: o.Record.ID, DeviceID: e.Kid, Decision: e})
	if a := w.lastAck(o.Record.ID); a.Outcome != protocol.OutcomeRejected || !strings.Contains(a.Detail, "another user") {
		t.Errorf("ack %+v", a)
	}
	if w.outcome(it.Key) != "pending" {
		t.Error("a decision for a user the phone does not belong to acted")
	}
}

// vince is re-pinned to another account while the adapter is stopped: it starts, without the saved chain that no
// longer matches, and takes up the original pin again once restored.
func TestRepinWhileStoppedStarts(t *testing.T) {
	w := newWorld(t)
	w.tick() // verifies and saves vince's chain
	repin := func(account string) *adapter.Trust {
		t.Helper()
		if err := adapter.TrustRemoveUser(w.dir, "vince"); err != nil {
			t.Fatal(err)
		}
		if err := adapter.TrustAddUser(w.dir, "vince", account); err != nil {
			t.Fatal(err)
		}
		tr, err := adapter.LoadTrust(w.dir)
		if err != nil {
			t.Fatalf("adapter does not start after re-pinning: %v", err)
		}
		return tr
	}
	other := "0000-1111-2222-3333-4444-5555-6666-7777"
	tr := repin(other)
	if len(tr.Dropped) != 1 || !strings.Contains(tr.Dropped[0].Error(), "vince") {
		t.Fatalf("dropped %v", tr.Dropped)
	}
	if _, heads := tr.Pins(); len(heads) != 0 || len(tr.Cards()) != 0 {
		t.Fatalf("chain kept for a pin it does not match: %+v", heads)
	}
	if errs := tr.Refresh(w.ctx, w.adHub.Roster); len(errs) != 1 || len(tr.Cards()) != 0 {
		t.Fatalf("hub's chain adopted for the wrong account: errs %v", errs)
	}

	tr = repin(w.account)
	if len(tr.Dropped) != 0 || len(tr.Cards()) != 1 {
		t.Fatalf("dropped %v, cards %v", tr.Dropped, tr.Cards())
	}
}
