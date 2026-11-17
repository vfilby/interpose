package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
)

// Pin is a user this adapter trusts: their id and account fingerprint (the hash of their genesis roster). Source says
// which trust source supplied it ("local", "ldap-user:bob", "ldap-group:warpgate_approvers"); trusted-users.json
// leaves it out, since everything in that file is local.
type Pin struct {
	User    string `json:"user"`
	Account string `json:"account"`
	Source  string `json:"source,omitempty"`
}

// same reports whether two pins name the same user and account, whatever their source.
func (p Pin) same(q Pin) bool { return p.User == q.User && p.Account == q.Account }

// A TrustSource is one place an adapter's trusted users come from (docs/DESIGN.md, D17).
type TrustSource struct {
	Kind string // SourceLocal, SourceLDAPUser or SourceLDAPGroup
	Name string // the uid or group for the LDAP kinds; "" for local
}

const (
	SourceLocal     = "local"      // trusted-users.json, written by `trust add-user`
	SourceLDAPUser  = "ldap-user"  // one directory user, by uid; their account is on their entry
	SourceLDAPGroup = "ldap-group" // every member of a directory group that has an account on their entry
)

func (s TrustSource) String() string {
	if s.Kind == SourceLocal {
		return SourceLocal
	}
	return s.Kind + ":" + s.Name
}

// ParseTrustSources reads the -trust setting: a comma-separated list of local, ldap-user:UID and ldap-group:CN. The
// empty string means local.
func ParseTrustSources(s string) ([]TrustSource, error) {
	var out []TrustSource
	seen := map[string]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		kind, name, _ := strings.Cut(f, ":")
		src := TrustSource{Kind: kind, Name: name}
		switch {
		case kind == SourceLocal && name == "":
		case (kind == SourceLDAPUser || kind == SourceLDAPGroup) && name != "":
		default:
			return nil, fmt.Errorf("trust source %q: want local, ldap-user:UID or ldap-group:GROUP", f)
		}
		if !seen[src.String()] {
			seen[src.String()] = true
			out = append(out, src)
		}
	}
	if len(out) == 0 {
		out = []TrustSource{{Kind: SourceLocal}}
	}
	return out, nil
}

// Directory is the read-only view of an LDAP directory the LDAP trust sources use (adapter/ldapdir implements it over
// go-ldap; tests use fakes). An Entry's Account is the raw value of the account attribute, "" if the entry has none;
// ParseAccount turns it into a Pin.
type Directory interface {
	// User finds one user by uid. ok false: there is no such user.
	User(ctx context.Context, uid string) (e Entry, ok bool, err error)
	// Group lists the members of a group that are user entries. ok false: there is no such group.
	Group(ctx context.Context, group string) (es []Entry, ok bool, err error)
}

type Entry struct {
	UID     string
	Account string
}

// ParseAccount reads the account attribute of a user's entry: the account fingerprint, or `user fingerprint` when
// the hub user id is not the uid (the hub keeps a user's id when they are renamed at the identity provider).
func ParseAccount(e Entry) (Pin, error) {
	user, account := strings.ToLower(e.UID), strings.TrimSpace(e.Account)
	if u, a, ok := strings.Cut(account, " "); ok {
		user, account = strings.ToLower(strings.TrimSpace(u)), strings.TrimSpace(a)
	}
	if account == "" {
		return Pin{}, errors.New("no account on the entry")
	}
	if !protocol.ValidUserID(user) || !isAccountFingerprint(account) {
		return Pin{}, fmt.Errorf("account attribute %q: want an account fingerprint like 3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0, or `user fingerprint`", e.Account)
	}
	return Pin{User: user, Account: account}, nil
}

func isAccountFingerprint(s string) bool {
	if len(s) != 39 {
		return false
	}
	for i, c := range s {
		switch {
		case i%5 == 4:
			if c != '-' {
				return false
			}
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

// TrustOptions configures where a Trust gets its users from. The zero value is local only.
type TrustOptions struct {
	Sources   []TrustSource // nil: local
	Directory Directory     // needed when any source is an LDAP one
	// Refresh is how often the LDAP sources are re-read to decide whose phones get a request (default 1 minute).
	// Decisions do not wait for it: Confirm asks the directory live.
	Refresh time.Duration
	// Stale is how long LDAP users keep getting asked when the directory cannot be read (default 15 minutes). After
	// that they are set aside until it answers again.
	Stale time.Duration
	Now   func() time.Time
}

// Change is one difference in who the adapter trusts, for the audit log.
type Change struct {
	Added bool
	Pin   Pin
}

// Trust is the adapter's own view of who may approve: pins from its trust sources (local: trusted-users.json, written
// by `interpose-adapter trust add-user`; LDAP: users and groups read from the directory) and, for each, the newest
// roster chain it has verified back to the pin (trusted-heads.json). Chains come through the hub, but nothing about
// them is taken on the hub's word: a chain must verify against the pin, and a verified head is never replaced by an
// older or a different one at the same seq.
type Trust struct {
	mu                  sync.RWMutex // the poll loop refreshes while the decision loop reads
	pinsPath, headsPath string
	opts                TrustOptions
	local               bool // SourceLocal is among the sources

	modTime   time.Time // of trusted-users.json
	localPins []Pin
	ldapPins  []Pin     // last read from the directory, every source together
	ldapAt    time.Time // when ldapPins were last read successfully
	ldapTried time.Time
	ldapErrs  []error // problems from the last read, repeated until the next one

	pins   []Pin                          // in force: local and LDAP pins merged
	chains map[string][]protocol.Envelope // user -> newest verified chain
	heads  map[string]protocol.Head
	saved  map[string][]protocol.Envelope // chains of users not pinned right now, kept so a user pinned again
	//                                        (an LDAP user after the directory was unreadable, say) takes up at
	//                                        the head last verified, not whatever the hub offers
	changes []Change
	notes   []error // chains set aside by merge, reported by the next Refresh

	// Dropped says which saved chains NewTrust set aside because they no longer verify against their pin.
	Dropped []error
}

const (
	pinsFile  = "trusted-users.json"
	headsFile = "trusted-heads.json"
)

// LoadTrust is NewTrust with local pins only.
func LoadTrust(dir string) (*Trust, error) { return NewTrust(dir, TrustOptions{}) }

// NewTrust reads the local pins and the saved chains. LDAP sources are read on the first Refresh, not here: an
// adapter must start whether or not the directory answers.
func NewTrust(dir string, o TrustOptions) (*Trust, error) {
	if o.Sources == nil {
		o.Sources = []TrustSource{{Kind: SourceLocal}}
	}
	if o.Refresh <= 0 {
		o.Refresh = time.Minute
	}
	if o.Stale <= 0 {
		o.Stale = 15 * time.Minute
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	t := &Trust{pinsPath: filepath.Join(dir, pinsFile), headsPath: filepath.Join(dir, headsFile), opts: o,
		chains: map[string][]protocol.Envelope{}, heads: map[string]protocol.Head{}, saved: map[string][]protocol.Envelope{}}
	for _, s := range o.Sources {
		switch {
		case s.Kind == SourceLocal:
			t.local = true
		case o.Directory == nil:
			return nil, fmt.Errorf("trust source %s needs an LDAP directory (-ldap-url)", s)
		}
	}
	b, err := os.ReadFile(t.headsPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &t.saved); err != nil {
			return nil, fmt.Errorf("%s: %w", t.headsPath, err)
		}
	}
	// Local pins are read now; merge takes up their saved chains. LDAP pins come with the first Refresh and take up
	// theirs then.
	if err := t.reload(true); err != nil {
		return nil, err
	}
	t.Dropped, t.notes = t.notes, nil
	return t, nil
}

// Sources lists the trust sources in force.
func (t *Trust) Sources() []TrustSource { return append([]TrustSource(nil), t.opts.Sources...) }

// Reload rereads the local pins if the file changed, so `trust add-user` / `remove-user` take effect without a restart.
func (t *Trust) Reload() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reload(false)
}

func (t *Trust) reload(force bool) error {
	if !t.local {
		t.localPins = nil
		t.merge()
		return nil
	}
	fi, err := os.Stat(t.pinsPath)
	if errors.Is(err, os.ErrNotExist) {
		t.localPins, t.modTime = nil, time.Time{}
		t.merge()
		return nil
	}
	if err != nil {
		return err
	}
	if !force && fi.ModTime().Equal(t.modTime) {
		return nil
	}
	pins, err := readPins(t.pinsPath)
	if err != nil {
		return err // a bad file must not silently change who is trusted
	}
	for i := range pins {
		pins[i].Source = SourceLocal
	}
	t.localPins, t.modTime = pins, fi.ModTime()
	t.merge()
	return nil
}

// merge recomputes the pins in force from the local and LDAP pins, records what changed, sets aside the chains of
// users no longer pinned and takes up the saved chain of a user newly pinned, if it verifies against the pin. A user
// named by two sources with the same account is pinned once, under the first source; named with two different
// accounts, they are not pinned at all until the sources agree (fail closed).
func (t *Trust) merge() {
	var pins []Pin
	conflict := map[string]bool{}
	for _, p := range append(append([]Pin(nil), t.localPins...), t.ldapPins...) {
		dup := false
		for _, q := range pins {
			if q.User == p.User {
				dup = true
				if q.Account != p.Account {
					conflict[p.User] = true
				}
			}
		}
		if !dup {
			pins = append(pins, p)
		}
	}
	keep := pins[:0]
	for _, p := range pins {
		if !conflict[p.User] {
			keep = append(keep, p)
		}
	}
	pins = keep
	for _, p := range pins {
		if !t.pinned(p) {
			t.changes = append(t.changes, Change{Added: true, Pin: p})
		}
	}
	for _, p := range t.pins {
		if !pinnedIn(pins, p) {
			t.changes = append(t.changes, Change{Pin: p})
		}
	}
	t.pins = pins
	for u, h := range t.heads {
		if !t.pinned(Pin{User: u, Account: h.Account}) {
			t.saved[u] = t.chains[u]
			delete(t.heads, u)
			delete(t.chains, u)
		}
	}
	for _, p := range t.pins {
		ch, ok := t.saved[p.User]
		if _, held := t.heads[p.User]; !ok || held {
			continue
		}
		delete(t.saved, p.User)
		h, err := protocol.VerifyChain(ch, p.User, p.Account)
		if err != nil {
			// Most likely the user was pinned to another account meanwhile. Either way the chain is not one for this
			// pin: drop it, and the next refresh verifies a fresh one from the pin. Nobody of that user can decide
			// until then.
			t.notes = append(t.notes, fmt.Errorf("%s: saved chain for %s does not verify against the pin; dropped: %w", t.headsPath, p.User, err))
			continue
		}
		t.chains[p.User], t.heads[p.User] = ch, h
	}
}

// TakeChanges returns the changes in who is trusted since the last call, oldest first.
func (t *Trust) TakeChanges() []Change {
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.changes
	t.changes = nil
	return c
}

// Refresh re-reads the LDAP sources when due, then fetches each pinned user's chain and adopts it if it verifies and
// is not older than what is known. It returns the problems found; users with a problem keep their last good head.
func (t *Trust) Refresh(ctx context.Context, fetch func(ctx context.Context, user string) ([]protocol.Envelope, error)) []error {
	errs := t.refreshDirectory(ctx)
	t.mu.Lock()
	pins := append([]Pin(nil), t.pins...)
	errs = append(errs, t.notes...)
	t.notes = nil
	t.mu.Unlock()
	changed := false
	for _, p := range pins {
		chain, err := fetch(ctx, p.User) // over the network: not under the lock
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: fetching roster: %w", p.User, err))
			continue
		}
		h, err := protocol.VerifyChain(chain, p.User, p.Account)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: roster does not verify: %w", p.User, err))
			continue
		}
		t.mu.Lock()
		old, known := t.heads[p.User]
		adopt := false
		switch {
		case !known:
			adopt = true
		case h.Roster.Seq > old.Roster.Seq && !extendsHead(chain, old):
			// A longer chain that branches off before the head already seen: e.g. a device removed in that head signing
			// an alternative history from a roster it was still on. Adopting it would undo the removal.
			errs = append(errs, fmt.Errorf("%s: hub offers roster v%d that does not build on v%d already seen: ignored", p.User, h.Roster.Seq, old.Roster.Seq))
		case h.Roster.Seq > old.Roster.Seq:
			adopt = true
		case h.Roster.Seq < old.Roster.Seq:
			errs = append(errs, fmt.Errorf("%s: hub offers roster v%d, older than v%d already seen: ignored", p.User, h.Roster.Seq, old.Roster.Seq))
		case string(h.Payload) != string(old.Payload):
			errs = append(errs, fmt.Errorf("%s: hub offers a different roster v%d than the one already seen: ignored", p.User, h.Roster.Seq))
		}
		// The pin may have changed while fetching; adopt only for the pin still in force.
		if adopt && t.pinned(p) {
			t.chains[p.User], t.heads[p.User] = chain, h
			changed = true
		}
		t.mu.Unlock()
	}
	if changed {
		t.mu.RLock()
		err := t.save()
		t.mu.RUnlock()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// RefreshDirectory reads the LDAP sources now if they are due, without touching rosters (for `trust list`).
func (t *Trust) RefreshDirectory(ctx context.Context) []error { return t.refreshDirectory(ctx) }

// refreshDirectory reads every LDAP source when the refresh interval has passed. A directory that cannot be read
// leaves the last pins in force until they go stale; then LDAP users stop being asked (decisions already ask the
// directory live, so nothing is approved on stale data either way).
func (t *Trust) refreshDirectory(ctx context.Context) []error {
	if t.opts.Directory == nil {
		return nil
	}
	now := t.opts.Now()
	t.mu.RLock()
	due := t.ldapTried.IsZero() || now.Sub(t.ldapTried) >= t.opts.Refresh
	last := t.ldapErrs
	t.mu.RUnlock()
	if !due {
		return last
	}
	pins, errs, read := t.readDirectory(ctx) // over the network: not under the lock
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ldapTried = now
	switch {
	case read:
		t.ldapPins, t.ldapAt = pins, now
	case !t.ldapAt.IsZero() && now.Sub(t.ldapAt) >= t.opts.Stale:
		errs = append(errs, fmt.Errorf("directory unreadable since %s: its users are set aside until it answers", t.ldapAt.Format(time.RFC3339)))
		t.ldapPins = nil
	}
	t.ldapErrs = errs
	t.merge()
	return errs
}

// readDirectory resolves every LDAP source to pins. read is false when any source could not be read (as opposed to
// answering that a user, group or entry is not usable): then the caller keeps the last good pins, all of them, rather
// than dropping the users of the source that failed.
func (t *Trust) readDirectory(ctx context.Context) (pins []Pin, errs []error, read bool) {
	pins = []Pin{}
	read = true
	for _, s := range t.opts.Sources {
		switch s.Kind {
		case SourceLDAPUser:
			e, ok, err := t.opts.Directory.User(ctx, s.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s, err))
				read = false
				continue
			}
			if !ok {
				errs = append(errs, fmt.Errorf("%s: no such user in the directory", s))
				continue
			}
			p, err := ParseAccount(e)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: not trusted: %w", s, err))
				continue
			}
			p.Source = s.String()
			pins = append(pins, p)
		case SourceLDAPGroup:
			es, ok, err := t.opts.Directory.Group(ctx, s.Name)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", s, err))
				read = false
				continue
			}
			if !ok {
				errs = append(errs, fmt.Errorf("%s: no such group in the directory", s))
				continue
			}
			for _, e := range es {
				p, err := ParseAccount(e)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: member %s not trusted: %w", s, e.UID, err))
					continue
				}
				p.Source = s.String()
				pins = append(pins, p)
			}
		}
	}
	return pins, errs, read
}

// Confirm asks, at decision time, whether user is still trusted by the source that pinned them, and returns that
// source. A local pin holds as long as the file says so. An LDAP pin is checked against the directory now, not against
// the last refresh: the user must still be named by the source, with the same account. Any directory error fails the
// check (fail closed).
func (t *Trust) Confirm(ctx context.Context, user string) (string, error) {
	t.mu.RLock()
	var pin Pin
	found := false
	for _, p := range t.pins {
		if p.User == user {
			pin, found = p, true
		}
	}
	t.mu.RUnlock()
	if !found {
		return "", fmt.Errorf("%s is not trusted", user)
	}
	kind, name, _ := strings.Cut(pin.Source, ":")
	switch kind {
	case SourceLocal:
		return pin.Source, nil
	case SourceLDAPUser:
		e, ok, err := t.opts.Directory.User(ctx, name)
		if err != nil {
			return pin.Source, fmt.Errorf("%s: directory check failed: %w", pin.Source, err)
		}
		if !ok {
			return pin.Source, fmt.Errorf("%s: no longer in the directory", pin.Source)
		}
		return pin.Source, confirmEntry(pin, e)
	case SourceLDAPGroup:
		es, ok, err := t.opts.Directory.Group(ctx, name)
		if err != nil {
			return pin.Source, fmt.Errorf("%s: directory check failed: %w", pin.Source, err)
		}
		if !ok {
			return pin.Source, fmt.Errorf("%s: group no longer in the directory", pin.Source)
		}
		for _, e := range es {
			if p, err := ParseAccount(e); err == nil && p.User == pin.User {
				return pin.Source, confirmEntry(pin, e)
			}
		}
		return pin.Source, fmt.Errorf("%s: %s is no longer a member", pin.Source, user)
	}
	return pin.Source, fmt.Errorf("%s: unknown trust source", pin.Source)
}

func confirmEntry(pin Pin, e Entry) error {
	p, err := ParseAccount(e)
	if err != nil {
		return fmt.Errorf("%s: %s: %w", pin.Source, pin.User, err)
	}
	if !p.same(pin) {
		return fmt.Errorf("%s: %s now has account %s, not %s", pin.Source, pin.User, p.Account, pin.Account)
	}
	return nil
}

// save writes the verified chains, those of users not pinned right now included (see saved).
func (t *Trust) save() error {
	all := make(map[string][]protocol.Envelope, len(t.chains)+len(t.saved))
	for u, ch := range t.saved {
		all[u] = ch
	}
	for u, ch := range t.chains {
		all[u] = ch
	}
	b, err := json.Marshal(all)
	if err != nil {
		return err
	}
	tmp := t.headsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, t.headsPath)
}

// extendsHead reports whether chain contains, at the head's position, exactly the head already verified.
func extendsHead(chain []protocol.Envelope, head protocol.Head) bool {
	i := head.Roster.Seq - 1
	if i >= len(chain) {
		return false
	}
	p, err := chain[i].PayloadBytes()
	return err == nil && string(p) == string(head.Payload)
}

func (t *Trust) pinned(p Pin) bool { return pinnedIn(t.pins, p) }

func pinnedIn(pins []Pin, p Pin) bool {
	for _, q := range pins {
		if q.same(p) {
			return true
		}
	}
	return false
}

// Holder is a device card as found on one trusted user's current roster.
type Holder struct {
	User string
	Card protocol.DeviceCard
}

// Holders finds a device on the current rosters of trusted users, sorted by user. Usually there is one; a device can
// be on the rosters of two users, and the decision says which of them it speaks for.
func (t *Trust) Holders(id string) []Holder {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []Holder
	for u, h := range t.heads {
		if c, ok := h.Devices[id]; ok {
			out = append(out, Holder{User: u, Card: c})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User < out[j].User })
	return out
}

// Cards lists every device on a trusted user's current roster.
func (t *Trust) Cards() []protocol.DeviceCard {
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []protocol.DeviceCard
	for _, h := range t.heads {
		for _, c := range h.Devices {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out
}

// Pins lists the trusted users with their current head (zero Head if none verified yet).
func (t *Trust) Pins() ([]Pin, map[string]protocol.Head) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	heads := make(map[string]protocol.Head, len(t.heads))
	for u, h := range t.heads {
		heads[u] = h
	}
	return append([]Pin(nil), t.pins...), heads
}

func readPins(path string) ([]Pin, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var pins []Pin
	if err := json.Unmarshal(b, &pins); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for _, p := range pins {
		if !protocol.ValidUserID(p.User) || !isAccountFingerprint(p.Account) {
			return nil, fmt.Errorf("%s: bad pin %+v", path, p)
		}
	}
	return pins, nil
}

func writePins(path string, pins []Pin) error {
	for i := range pins {
		pins[i].Source = "" // everything in the file is local
	}
	b, err := json.MarshalIndent(pins, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// TrustAddUser pins a user by account fingerprint (from their first phone, or the hub's user list).
func TrustAddUser(dir, user, account string) error {
	if !protocol.ValidUserID(user) || !isAccountFingerprint(account) {
		return errors.New("want a user id and an account fingerprint like 3f2a-91c0-77de-0b14-5c2e-aa01-9d3b-71f0")
	}
	path := filepath.Join(dir, pinsFile)
	pins, err := readPins(path)
	if err != nil {
		return err
	}
	for _, p := range pins {
		if p.User == user {
			return fmt.Errorf("user %s is already trusted (account %s); remove-user first to change it", user, p.Account)
		}
	}
	return writePins(path, append(pins, Pin{User: user, Account: account}))
}

// TrustRemoveUser stops trusting a user.
func TrustRemoveUser(dir, user string) error {
	path := filepath.Join(dir, pinsFile)
	pins, err := readPins(path)
	if err != nil {
		return err
	}
	keep := pins[:0]
	for _, p := range pins {
		if p.User != user {
			keep = append(keep, p)
		}
	}
	if len(keep) == len(pins) {
		return fmt.Errorf("user %s is not trusted", user)
	}
	return writePins(path, keep)
}
