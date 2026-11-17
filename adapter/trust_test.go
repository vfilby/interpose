package adapter

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

const (
	fpA = "3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0"
	fpB = "0000-1111-2222-3333-4444-5555-6666-7777"
)

// fakeDir is a directory in memory: users by uid with their account attribute, groups by name with member uids.
type fakeDir struct {
	users  map[string]string // uid -> account attribute ("" for none)
	groups map[string][]string
	err    error // every call fails with it when set
	calls  int
}

func (d *fakeDir) User(_ context.Context, uid string) (Entry, bool, error) {
	d.calls++
	if d.err != nil {
		return Entry{}, false, d.err
	}
	a, ok := d.users[uid]
	return Entry{UID: uid, Account: a}, ok, nil
}

func (d *fakeDir) Group(_ context.Context, g string) ([]Entry, bool, error) {
	d.calls++
	if d.err != nil {
		return nil, false, d.err
	}
	uids, ok := d.groups[g]
	if !ok {
		return nil, false, nil
	}
	var out []Entry
	for _, u := range uids {
		if a, ok := d.users[u]; ok {
			out = append(out, Entry{UID: u, Account: a})
		}
	}
	return out, true, nil
}

func sources(t *testing.T, s string) []TrustSource {
	t.Helper()
	srcs, err := ParseTrustSources(s)
	if err != nil {
		t.Fatal(err)
	}
	return srcs
}

func TestParseTrustSources(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "local"},
		{"local", "local"},
		{" local , ldap-group:ops ,ldap-user:bob,local", "local ldap-group:ops ldap-user:bob"},
		{"ldap-group:ops", "ldap-group:ops"},
	} {
		srcs, err := ParseTrustSources(c.in)
		if err != nil {
			t.Fatalf("%q: %v", c.in, err)
		}
		var got []string
		for _, s := range srcs {
			got = append(got, s.String())
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%q: %v, want %s", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"ldap", "ldap-group", "ldap-group:", "local:x", "file:/x", "group:ops"} {
		if _, err := ParseTrustSources(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseAccount(t *testing.T) {
	for _, c := range []struct {
		e    Entry
		user string
	}{
		{Entry{UID: "Alice", Account: fpA}, "alice"},
		{Entry{UID: "alice", Account: "  " + fpA + "\n"}, "alice"},
		{Entry{UID: "alice.old", Account: "alice " + fpA}, "alice"}, // renamed at the provider; the hub kept "alice"
	} {
		p, err := ParseAccount(c.e)
		if err != nil || p.User != c.user || p.Account != fpA {
			t.Errorf("%+v: %+v, %v", c.e, p, err)
		}
	}
	for _, bad := range []Entry{
		{UID: "alice"},
		{UID: "alice", Account: "3f2a-91c0"},
		{UID: "alice", Account: strings.ToUpper(fpA)},
		{UID: "Al ice", Account: fpA},
		{UID: "alice", Account: "Bob " + fpA + " extra"},
		{UID: "alice", Account: "3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71fg"},
	} {
		if _, err := ParseAccount(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

// pinsOf renders the pins in force as "user=account@source" for comparison.
func pinsOf(t *Trust) string {
	pins, _ := t.Pins()
	var out []string
	for _, p := range pins {
		out = append(out, p.User+"="+p.Account+"@"+p.Source)
	}
	return strings.Join(out, " ")
}

func changesOf(cs []Change) string {
	var out []string
	for _, c := range cs {
		sign := "-"
		if c.Added {
			sign = "+"
		}
		out = append(out, sign+c.Pin.User+"@"+c.Pin.Source)
	}
	return strings.Join(out, " ")
}

// Nothing in the directory is read until the first Refresh; then users and group members with an account are pinned
// under their source, and every change is reported once.
func TestLDAPSourcesPinUsers(t *testing.T) {
	dir := t.TempDir()
	d := &fakeDir{users: map[string]string{"alice": fpA, "bob": fpB, "carol": "", "dave": "junk"},
		groups: map[string][]string{"ops": {"alice", "carol", "dave", "nobody"}}}
	tr, err := NewTrust(dir, TrustOptions{Sources: sources(t, "ldap-group:ops,ldap-user:bob,ldap-user:erin"), Directory: d})
	if err != nil {
		t.Fatal(err)
	}
	if got := pinsOf(tr); got != "" || d.calls != 0 {
		t.Fatalf("before the first refresh: pins %q, %d directory calls", got, d.calls)
	}
	errs := tr.RefreshDirectory(context.Background())
	if got, want := pinsOf(tr), "alice="+fpA+"@ldap-group:ops bob="+fpB+"@ldap-user:bob"; got != want {
		t.Fatalf("pins %q, want %q", got, want)
	}
	if got := changesOf(tr.TakeChanges()); got != "+alice@ldap-group:ops +bob@ldap-user:bob" {
		t.Fatalf("changes %q", got)
	}
	if len(tr.TakeChanges()) != 0 {
		t.Fatal("changes reported twice")
	}
	// carol (no account), dave (unusable account) and erin (no such user) are each said once per read.
	var msgs []string
	for _, e := range errs {
		msgs = append(msgs, e.Error())
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{"member carol not trusted: no account", "member dave not trusted: account attribute", "ldap-user:erin: no such user"} {
		if !strings.Contains(all, want) {
			t.Errorf("errors lack %q:\n%s", want, all)
		}
	}
	if len(errs) != 3 {
		t.Errorf("%d errors:\n%s", len(errs), all)
	}
}

// A user pinned locally and by LDAP with the same account is pinned once; with different accounts, not at all.
func TestLocalAndLDAPTogether(t *testing.T) {
	dir := t.TempDir()
	if err := TrustAddUser(dir, "alice", fpA); err != nil {
		t.Fatal(err)
	}
	if err := TrustAddUser(dir, "bob", fpA); err != nil {
		t.Fatal(err)
	}
	d := &fakeDir{users: map[string]string{"alice": fpA, "bob": fpB, "carol": fpB}, groups: map[string][]string{"ops": {"alice", "bob", "carol"}}}
	tr, err := NewTrust(dir, TrustOptions{Sources: sources(t, "local,ldap-group:ops"), Directory: d})
	if err != nil {
		t.Fatal(err)
	}
	if got := pinsOf(tr); got != "alice="+fpA+"@local bob="+fpA+"@local" {
		t.Fatalf("local pins %q", got)
	}
	tr.RefreshDirectory(context.Background())
	if got, want := pinsOf(tr), "alice="+fpA+"@local carol="+fpB+"@ldap-group:ops"; got != want {
		t.Fatalf("pins %q, want %q (bob has two accounts and must not be pinned)", got, want)
	}
	if got := changesOf(tr.TakeChanges()); got != "+alice@local +bob@local +carol@ldap-group:ops -bob@local" {
		t.Fatalf("changes %q", got)
	}
	// Removing the local pin for bob ends the conflict: bob is pinned by LDAP.
	if err := TrustRemoveUser(dir, "bob"); err != nil {
		t.Fatal(err)
	}
	tr.modTime = time.Time{} // the file changed within the same second; force the reload
	if err := tr.Reload(); err != nil {
		t.Fatal(err)
	}
	if got, want := pinsOf(tr), "alice="+fpA+"@local bob="+fpB+"@ldap-group:ops carol="+fpB+"@ldap-group:ops"; got != want {
		t.Fatalf("pins %q, want %q", got, want)
	}
}

// Confirm asks the directory live: a user who left the group, lost their account or changed it is refused, and so is
// everyone from LDAP while the directory cannot be read. Local pins need no directory.
func TestConfirm(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := TrustAddUser(dir, "lee", fpA); err != nil {
		t.Fatal(err)
	}
	d := &fakeDir{users: map[string]string{"alice": fpA, "bob": fpB}, groups: map[string][]string{"ops": {"alice"}}}
	tr, err := NewTrust(dir, TrustOptions{Sources: sources(t, "local,ldap-group:ops,ldap-user:bob"), Directory: d})
	if err != nil {
		t.Fatal(err)
	}
	tr.RefreshDirectory(ctx)
	for _, u := range []string{"lee", "alice", "bob"} {
		if _, err := tr.Confirm(ctx, u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	calls := d.calls
	if _, err := tr.Confirm(ctx, "lee"); err != nil || d.calls != calls {
		t.Error("a local pin asked the directory")
	}
	if _, err := tr.Confirm(ctx, "zed"); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Errorf("unknown user: %v", err)
	}

	d.groups["ops"] = nil // alice leaves the group: no refresh has happened, the pins still list her
	if src, err := tr.Confirm(ctx, "alice"); err == nil || !strings.Contains(err.Error(), "no longer a member") || src != "ldap-group:ops" {
		t.Errorf("left the group: %v (%s)", err, src)
	}
	d.groups["ops"] = []string{"alice"}
	d.users["alice"] = fpB // the account on alice's entry changed
	if _, err := tr.Confirm(ctx, "alice"); err == nil || !strings.Contains(err.Error(), "now has account "+fpB) {
		t.Errorf("account changed: %v", err)
	}
	d.users["alice"] = fpA
	delete(d.users, "bob")
	if _, err := tr.Confirm(ctx, "bob"); err == nil || !strings.Contains(err.Error(), "no longer in the directory") {
		t.Errorf("user gone: %v", err)
	}
	d.users["bob"] = ""
	if _, err := tr.Confirm(ctx, "bob"); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Errorf("account removed: %v", err)
	}
	d.err = errors.New("connection refused")
	if _, err := tr.Confirm(ctx, "alice"); err == nil || !strings.Contains(err.Error(), "directory check failed") {
		t.Errorf("directory down: %v", err)
	}
	if _, err := tr.Confirm(ctx, "lee"); err != nil {
		t.Errorf("directory down must not affect a local pin: %v", err)
	}
}

// While the directory cannot be read its users keep being asked, on the last good pins, until they go stale. A
// failure of one source keeps every source's pins, not just the others'.
func TestDirectoryOutage(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	d := &fakeDir{users: map[string]string{"alice": fpA, "bob": fpB}, groups: map[string][]string{"ops": {"alice"}}}
	tr, err := NewTrust(t.TempDir(), TrustOptions{Sources: sources(t, "ldap-group:ops,ldap-user:bob"), Directory: d,
		Refresh: time.Minute, Stale: 10 * time.Minute, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	tr.RefreshDirectory(ctx)
	want := "alice=" + fpA + "@ldap-group:ops bob=" + fpB + "@ldap-user:bob"
	if got := pinsOf(tr); got != want {
		t.Fatalf("pins %q", got)
	}
	// Not due yet: no call, same answer.
	now = now.Add(30 * time.Second)
	calls := d.calls
	tr.RefreshDirectory(ctx)
	if d.calls != calls {
		t.Fatal("read the directory before the refresh interval")
	}

	d.err = errors.New("connection refused")
	now = now.Add(time.Minute)
	errs := tr.RefreshDirectory(ctx)
	if len(errs) == 0 || pinsOf(tr) != want {
		t.Fatalf("outage: errs %v, pins %q", errs, pinsOf(tr))
	}
	now = now.Add(11 * time.Minute)
	errs = tr.RefreshDirectory(ctx)
	if got := pinsOf(tr); got != "" {
		t.Fatalf("stale pins kept: %q", got)
	}
	found := false
	for _, e := range errs {
		found = found || strings.Contains(e.Error(), "set aside")
	}
	if !found {
		t.Fatalf("errs %v", errs)
	}
	if got := changesOf(tr.TakeChanges()); got != "+alice@ldap-group:ops +bob@ldap-user:bob -alice@ldap-group:ops -bob@ldap-user:bob" {
		t.Fatalf("changes %q", got)
	}

	// Back: pinned again on the next due refresh.
	d.err = nil
	now = now.Add(time.Minute)
	tr.RefreshDirectory(ctx)
	if pinsOf(tr) != want {
		t.Fatalf("pins %q after the directory is back", pinsOf(tr))
	}
	d.groups = nil // Group answers "no such group": a definite answer, alice is dropped
	now = now.Add(time.Minute)
	tr.RefreshDirectory(ctx)
	if got := pinsOf(tr); got != "bob="+fpB+"@ldap-user:bob" {
		t.Fatalf("pins %q", got)
	}
	// A partial failure keeps everyone, alice included once she is back.
	d.groups = map[string][]string{"ops": {"alice"}}
	now = now.Add(time.Minute)
	tr.RefreshDirectory(ctx)
	partial := &partialDir{fakeDir: d}
	tr.opts.Directory = partial
	now = now.Add(time.Minute)
	errs = tr.RefreshDirectory(ctx)
	if len(errs) != 1 || pinsOf(tr) != want {
		t.Fatalf("partial failure: errs %v, pins %q", errs, pinsOf(tr))
	}
}

// partialDir answers for groups and fails for users.
type partialDir struct{ *fakeDir }

func (p *partialDir) User(context.Context, string) (Entry, bool, error) {
	return Entry{}, false, errors.New("timeout")
}

// A verified chain is kept on disk for a user who is pinned again later (by LDAP after a restart or an outage), so
// the hub cannot offer an older roster then. The chain is held only while its pin is in force.
func TestSavedChainSurvivesForLDAPUsers(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	phone, _ := softdevice.New("phone")
	now := time.Now()
	g, err := phone.Genesis("alice", now)
	if err != nil {
		t.Fatal(err)
	}
	chain := []protocol.Envelope{g}
	h, err := protocol.VerifyChain(chain, "alice", "")
	if err != nil {
		t.Fatal(err)
	}
	fetch := func(context.Context, string) ([]protocol.Envelope, error) { return chain, nil }
	noFetch := func(context.Context, string) ([]protocol.Envelope, error) { return nil, errors.New("hub down") }

	d := &fakeDir{users: map[string]string{"alice": h.Account}, groups: map[string][]string{"ops": {"alice"}}}
	tr, err := NewTrust(dir, TrustOptions{Sources: sources(t, "ldap-group:ops"), Directory: d})
	if err != nil {
		t.Fatal(err)
	}
	if errs := tr.Refresh(ctx, fetch); len(errs) != 0 || len(tr.Cards()) != 1 {
		t.Fatalf("errs %v, cards %d", errs, len(tr.Cards()))
	}

	// Restart: the chain is on disk; it is taken up when the directory pins alice again, with no roster fetch.
	tr, err = NewTrust(dir, TrustOptions{Sources: sources(t, "ldap-group:ops"), Directory: d})
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.Cards()) != 0 {
		t.Fatal("cards before the directory was read")
	}
	if errs := tr.Refresh(ctx, noFetch); len(tr.Cards()) != 1 {
		t.Fatalf("saved chain not taken up: errs %v", errs)
	}

	// Alice leaves and comes back: the chain is set aside, then taken up again; the file keeps it meanwhile.
	d.groups["ops"] = nil
	tr.ldapTried = time.Time{}
	tr.Refresh(ctx, noFetch)
	if len(tr.Cards()) != 0 {
		t.Fatal("cards for a user no longer pinned")
	}
	d.groups["ops"] = []string{"alice"}
	tr.ldapTried = time.Time{}
	tr.Refresh(ctx, noFetch)
	if len(tr.Cards()) != 1 {
		t.Fatal("saved chain not taken up again")
	}

	// Pinned to another account: the saved chain does not verify and is dropped; a fetch from the pin is needed.
	d.users["alice"] = fpB
	tr.ldapTried = time.Time{}
	errs := tr.Refresh(ctx, noFetch)
	if len(tr.Cards()) != 0 {
		t.Fatal("a chain for another pin was kept")
	}
	dropped := false
	for _, e := range errs {
		dropped = dropped || strings.Contains(e.Error(), "does not verify against the pin")
	}
	if !dropped {
		t.Fatalf("errs %v", errs)
	}
	d.users["alice"] = h.Account
	tr.ldapTried = time.Time{}
	if tr.Refresh(ctx, noFetch); len(tr.Cards()) != 0 {
		t.Fatal("a dropped chain came back without a fetch")
	}
	if errs := tr.Refresh(ctx, fetch); len(tr.Cards()) != 1 {
		t.Fatalf("errs %v", errs)
	}
	if _, err := LoadTrust(filepath.Join(dir)); err != nil {
		t.Fatal(err)
	}
}
