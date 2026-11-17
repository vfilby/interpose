// Package cli is the command line every adapter binary shares. An adapter's main supplies its Source; the key, the
// trust list, the hub connection and the run loop are the same for all of them:
//
//	PROG key   [-dir D]                         create the signing key if missing; print the public key to register at the hub
//	PROG trust add-user [-dir D] USER ACCOUNT   trust a user's devices (ACCOUNT: their account fingerprint)
//	PROG trust remove-user [-dir D] USER
//	PROG trust list [-dir D] [trust flags]      users by source, and the devices on their last verified roster
//	PROG run -id ID -hub URL [-source S] [-dir D] [trust flags] [source flags]
//
// The directory holds signing.key (0400), trusted-users.json, trusted-heads.json (verified rosters), hub-token (0400,
// from the hub's management UI), state.json and audit.jsonl.
//
// Trust flags choose where trusted users come from (-trust: local, ldap-user:UID, ldap-group:GROUP) and how to reach
// the directory (-ldap-*). Each has an environment variable of the same meaning (INTERPOSE_TRUST, LDAP_URL, …), so a
// compose file's .env can carry them; docs/runbooks/ldap.md.
package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapter/ldapdir"
	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
)

// envOr is a flag default from the environment.
func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// trustFlags registers the trust flags and returns what builds the TrustOptions once they are parsed.
func trustFlags(fs *flag.FlagSet) func() (adapter.TrustOptions, *ldapdir.Client, error) {
	sources := fs.String("trust", envOr("INTERPOSE_TRUST", "local"), "trust sources, comma-separated: local, ldap-user:UID, ldap-group:GROUP (INTERPOSE_TRUST)")
	url := fs.String("ldap-url", envOr("LDAP_URL", ""), "the directory: ldaps://host[:636] or ldap://host[:389] with StartTLS (LDAP_URL)")
	bindDN := fs.String("ldap-bind-dn", envOr("LDAP_BIND_DN", ""), "read-only account to bind as (LDAP_BIND_DN)")
	passFile := fs.String("ldap-bind-password-file", envOr("LDAP_BIND_PASSWORD_FILE", "/run/secrets/ldap-password"), "file holding its password (LDAP_BIND_PASSWORD_FILE)")
	caFile := fs.String("ldap-ca-file", envOr("LDAP_CA_FILE", ""), "PEM file to verify the directory's certificate; default: system roots (LDAP_CA_FILE)")
	plain := fs.Bool("ldap-plain", envOr("LDAP_PLAIN", "") == "true", "allow ldap:// without StartTLS: only on the adapter's own private network (LDAP_PLAIN=true)")
	userBase := fs.String("ldap-user-base", envOr("LDAP_USER_BASE", ""), "base DN of users, e.g. ou=people,dc=example,dc=org (LDAP_USER_BASE)")
	groupBase := fs.String("ldap-group-base", envOr("LDAP_GROUP_BASE", ""), "base DN of groups; default: the user base (LDAP_GROUP_BASE)")
	userAttr := fs.String("ldap-user-attr", envOr("LDAP_USER_ATTR", "uid"), "attribute that is a user's uid (LDAP_USER_ATTR)")
	accountAttr := fs.String("ldap-account-attr", envOr("LDAP_ACCOUNT_ATTR", "interposeAccount"), "attribute on a user's entry holding their account fingerprint (LDAP_ACCOUNT_ATTR)")
	groupAttr := fs.String("ldap-group-attr", envOr("LDAP_GROUP_ATTR", "cn"), "attribute that names a group (LDAP_GROUP_ATTR)")
	refresh := fs.Duration("ldap-refresh", mustDuration(envOr("LDAP_REFRESH", "1m")), "how often LDAP sources are re-read to decide whose phones get a request; decisions always ask live (LDAP_REFRESH)")
	return func() (adapter.TrustOptions, *ldapdir.Client, error) {
		srcs, err := adapter.ParseTrustSources(*sources)
		if err != nil {
			return adapter.TrustOptions{}, nil, err
		}
		o := adapter.TrustOptions{Sources: srcs, Refresh: *refresh}
		ldap := false
		for _, s := range srcs {
			ldap = ldap || s.Kind != adapter.SourceLocal
		}
		if !ldap {
			return o, nil, nil
		}
		if *url == "" {
			return o, nil, fmt.Errorf("-trust %s needs the directory: -ldap-url (LDAP_URL)", *sources)
		}
		pw, err := os.ReadFile(*passFile)
		if err != nil {
			return o, nil, fmt.Errorf("LDAP bind password: %w", err)
		}
		c, err := ldapdir.New(ldapdir.Config{URL: *url, BindDN: *bindDN, Password: strings.TrimSpace(string(pw)), CAFile: *caFile,
			Plain: *plain, UserBase: *userBase, GroupBase: *groupBase, UserAttr: *userAttr, AccountAttr: *accountAttr, GroupAttr: *groupAttr})
		if err != nil {
			return o, nil, err
		}
		o.Directory = c
		return o, c, nil
	}
}

func mustDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP_REFRESH %q is not a duration; using 1m\n", s)
		return time.Minute
	}
	return d
}

func sourceNames(srcs []adapter.TrustSource) string {
	names := make([]string, len(srcs))
	for i, s := range srcs {
		names[i] = s.String()
	}
	return strings.Join(names, ",")
}

// Source is one service an adapter binary can guard.
type Source struct {
	Name string
	// Flags registers the source's own flags on the run command, and returns what builds the source once they are
	// parsed. The constructor may start helpers that stop when ctx ends.
	Flags func(fs *flag.FlagSet) func(ctx context.Context, log *slog.Logger) (adapter.Source, error)
}

// Main runs the command line for prog and exits. The first source is the default for -source.
func Main(prog string, sources ...Source) {
	if len(sources) == 0 {
		panic("cli.Main: no sources")
	}
	c := &cmd{prog: prog, sources: sources}
	if len(os.Args) < 2 {
		c.usage()
	}
	var err error
	switch os.Args[1] {
	case "key":
		err = c.key(os.Args[2:])
	case "trust":
		err = c.trust(os.Args[2:])
	case "run":
		err = c.run(os.Args[2:])
	default:
		c.usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
}

type cmd struct {
	prog    string
	sources []Source
}

func (c *cmd) usage() {
	fmt.Fprintf(os.Stderr, "usage: %s key [-dir D] | trust add-user [-dir D] USER ACCOUNT | trust remove-user [-dir D] USER | trust list [-dir D] [trust flags] | run [flags]  (flags before arguments; `run -h` lists them)\n", c.prog)
	os.Exit(2)
}

func loadOrCreateKey(dir string, create bool) (ed25519.PrivateKey, error) {
	p := filepath.Join(dir, "signing.key")
	b, err := os.ReadFile(p)
	if err == nil {
		seed, err := protocol.UnB64(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a base64url Ed25519 seed", p)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, []byte(protocol.B64(k.Seed())+"\n"), 0o400)
}

func (c *cmd) key(args []string) error {
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	_ = fs.Parse(args)
	k, err := loadOrCreateKey(*dir, true)
	if err != nil {
		return err
	}
	pub := k.Public().(ed25519.PublicKey)
	fmt.Printf("public key:  %s\nfingerprint: %s\n", protocol.B64(pub), protocol.Fingerprint(pub))
	return nil
}

func (c *cmd) trust(args []string) error {
	if len(args) < 1 {
		c.usage()
	}
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	trustOpts := trustFlags(fs)
	_ = fs.Parse(args[1:])
	switch args[0] {
	case "add-user":
		if fs.NArg() != 2 {
			c.usage()
		}
		if err := os.MkdirAll(*dir, 0o700); err != nil {
			return err
		}
		if err := adapter.TrustAddUser(*dir, fs.Arg(0), fs.Arg(1)); err != nil {
			return err
		}
		fmt.Printf("trusting user %s, account %s\n(the running adapter picks it up on its next poll; check the account fingerprint against the phone)\n", fs.Arg(0), fs.Arg(1))
		if srcs, err := adapter.ParseTrustSources(envOr("INTERPOSE_TRUST", "local")); err == nil && !hasLocal(srcs) {
			fmt.Printf("note: INTERPOSE_TRUST=%s leaves out local, so the running adapter does not use trusted-users.json\n", sourceNames(srcs))
		}
	case "remove-user":
		if fs.NArg() != 1 {
			c.usage()
		}
		return adapter.TrustRemoveUser(*dir, fs.Arg(0))
	case "list":
		o, _, err := trustOpts()
		if err != nil {
			return err
		}
		t, err := adapter.NewTrust(*dir, o)
		if err != nil {
			return err
		}
		for _, err := range t.RefreshDirectory(context.Background()) {
			fmt.Printf("warning: %v\n", err)
		}
		fmt.Printf("trust sources: %s\n", sourceNames(t.Sources()))
		pins, heads := t.Pins()
		for _, p := range pins {
			h, ok := heads[p.User]
			if !ok {
				fmt.Printf("%s  account %s  (roster not verified yet)  [%s]\n", p.User, p.Account, p.Source)
				continue
			}
			fmt.Printf("%s  account %s  roster v%d  [%s]\n", p.User, p.Account, h.Roster.Seq, p.Source)
			for _, c := range h.Devices {
				ak, _ := protocol.UnB64(c.ApproveKey)
				fmt.Printf("    %s  %q\n", protocol.Fingerprint(ak), c.Name)
			}
		}
	default:
		c.usage()
	}
	return nil
}

func (c *cmd) run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	id := fs.String("id", "", "adapter id, as registered at the hub")
	names := make([]string, len(c.sources))
	builders := map[string]func(context.Context, *slog.Logger) (adapter.Source, error){}
	for i, s := range c.sources {
		names[i] = s.Name
		builders[s.Name] = s.Flags(fs)
	}
	source := fs.String("source", c.sources[0].Name, strings.Join(names, " | "))
	hubURL := fs.String("hub", "http://127.0.0.1:8740", "hub API base URL")
	ttl := fs.Duration("ttl", 15*time.Minute, "how long a request stays answerable")
	poll := fs.Duration("poll", 3*time.Second, "how often to poll the service")
	auditMB := fs.Int64("audit-max-mb", 64, "start a new audit.jsonl past this many MiB (0: never)")
	auditKeep := fs.Int("audit-keep", 8, "rotated audit files kept: audit.jsonl.1 (newest) … audit.jsonl.N")
	trustOpts := trustFlags(fs)
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	if err := adapter.CheckURL("-hub", *hubURL); err != nil {
		return err
	}
	build, ok := builders[*source]
	if !ok {
		return fmt.Errorf("unknown source %q (this binary has: %s)", *source, strings.Join(names, ", "))
	}
	topts, ldap, err := trustOpts()
	if err != nil {
		return err
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("adapter", *id)
	key, err := loadOrCreateKey(*dir, false)
	if err != nil {
		return fmt.Errorf("signing key (run `%s key` first): %w", c.prog, err)
	}
	tok, err := os.ReadFile(filepath.Join(*dir, "hub-token"))
	if err != nil {
		return fmt.Errorf("hub token (from the hub's management UI): %w", err)
	}
	trust, err := adapter.NewTrust(*dir, topts)
	if err != nil {
		return err
	}
	if ldap != nil && ldap.Plain() {
		log.Warn("LDAP lookups go in clear (LDAP_PLAIN): the bind password and every answer can be read on the way; keep the directory on the adapter's own private network")
	}
	a, err := audit.OpenRotating(filepath.Join(*dir, "audit.jsonl"), *auditMB<<20, *auditKeep)
	if err != nil {
		return err
	}
	defer a.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	src, err := build(ctx, log)
	if err != nil {
		return err
	}
	ad, err := adapter.New(adapter.Config{ID: *id, Key: key, StateFile: filepath.Join(*dir, "state.json"), TTL: *ttl, Poll: *poll},
		src, &adapter.HubClient{Base: *hubURL, Token: strings.TrimSpace(string(tok))}, trust, a, log)
	if err != nil {
		return err
	}
	for _, err := range trust.Dropped {
		log.Warn("trusted users", "err", err)
	}
	pub := key.Public().(ed25519.PublicKey)
	log.Info("started", "source", *source, "hub", *hubURL, "key", protocol.Fingerprint(pub), "trust", sourceNames(trust.Sources()),
		"trusted_devices", len(trust.Cards()))
	ad.Run(ctx)
	log.Info("stopped")
	return nil
}

func hasLocal(srcs []adapter.TrustSource) bool {
	for _, s := range srcs {
		if s.Kind == adapter.SourceLocal {
			return true
		}
	}
	return false
}
