// Package ldapdir reads users and groups from an LDAP directory for the adapter's LDAP trust sources
// (adapter.Directory). It binds read-only, over LDAPS or StartTLS, and looks things up as asked: there is no cache
// here, so a check at decision time is a fresh answer from the directory.
package ldapdir

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/vfilby/interpose/adapter"
)

type Config struct {
	URL      string // ldaps://host[:636], or ldap://host[:389] (StartTLS, unless Plain)
	BindDN   string // a read-only account that can read users, groups and the account attribute
	Password string
	CAFile   string // PEM file to verify the server with; "" uses the system roots
	// Plain allows ldap:// without StartTLS: the bind password and every answer travel in clear. Only for a
	// directory on the adapter's own private network (a Docker network in the same stack).
	Plain bool

	UserBase    string // where users are searched, e.g. ou=people,dc=example,dc=org
	GroupBase   string // where groups are searched, e.g. ou=groups,dc=example,dc=org
	UserAttr    string // the attribute that is the uid (default uid)
	AccountAttr string // the attribute holding the account fingerprint (default interposeAccount)
	GroupAttr   string // the attribute that names a group (default cn)
	Timeout     time.Duration
}

type Client struct {
	cfg  Config
	tls  *tls.Config
	host string
}

// New checks the configuration and reads the CA file. It does not connect: the first lookup does.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || (u.Scheme != "ldaps" && u.Scheme != "ldap") {
		return nil, fmt.Errorf("LDAP URL %q: want ldaps://host[:port] or ldap://host[:port]", cfg.URL)
	}
	if cfg.BindDN == "" || cfg.Password == "" {
		return nil, errors.New("LDAP bind DN and password are required")
	}
	if cfg.UserBase == "" {
		return nil, errors.New("LDAP user base DN is required")
	}
	if cfg.GroupBase == "" {
		cfg.GroupBase = cfg.UserBase
	}
	if cfg.UserAttr == "" {
		cfg.UserAttr = "uid"
	}
	if cfg.AccountAttr == "" {
		cfg.AccountAttr = "interposeAccount"
	}
	if cfg.GroupAttr == "" {
		cfg.GroupAttr = "cn"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	for _, a := range []string{cfg.UserAttr, cfg.AccountAttr, cfg.GroupAttr} {
		if !attrName(a) {
			return nil, fmt.Errorf("LDAP attribute name %q: want letters, digits and dashes", a)
		}
	}
	c := &Client{cfg: cfg, host: u.Hostname(), tls: &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s: no certificates found", cfg.CAFile)
		}
		c.tls.RootCAs = pool
	}
	return c, nil
}

// Plain reports whether lookups go in clear (Config.Plain with an ldap:// URL), for the adapter to say so at start.
func (c *Client) Plain() bool { return c.cfg.Plain && strings.HasPrefix(c.cfg.URL, "ldap://") }

func attrName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// connect dials, secures and binds a connection. Every lookup gets its own: they are rare (once a minute, and one
// per decision), and a connection that is never reused has no stale state to reason about.
func (c *Client) connect(ctx context.Context) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: c.cfg.Timeout}
	conn, err := ldap.DialURL(c.cfg.URL, ldap.DialWithDialer(d), ldap.DialWithTLSConfig(c.tls))
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", c.cfg.URL, err)
	}
	conn.SetTimeout(c.cfg.Timeout)
	if strings.HasPrefix(c.cfg.URL, "ldap://") && !c.cfg.Plain {
		if err := conn.StartTLS(c.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("StartTLS with %s: %w (set LDAP_PLAIN=true only for a directory on the adapter's own private network)", c.host, err)
		}
	}
	if err := conn.Bind(c.cfg.BindDN, c.cfg.Password); err != nil {
		conn.Close()
		return nil, fmt.Errorf("binding as %s: %w", c.cfg.BindDN, err)
	}
	return conn, nil
}

// User finds one user by uid under the user base. Two entries with the same uid is an error, not a choice.
func (c *Client) User(ctx context.Context, uid string) (adapter.Entry, bool, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return adapter.Entry{}, false, err
	}
	defer conn.Close()
	return c.user(conn, uid)
}

func (c *Client) user(conn *ldap.Conn, uid string) (adapter.Entry, bool, error) {
	res, err := conn.Search(ldap.NewSearchRequest(c.cfg.UserBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		fmt.Sprintf("(%s=%s)", c.cfg.UserAttr, ldap.EscapeFilter(uid)), []string{c.cfg.UserAttr, c.cfg.AccountAttr}, nil))
	if err != nil {
		return adapter.Entry{}, false, fmt.Errorf("searching for user %s: %w", uid, err)
	}
	switch len(res.Entries) {
	case 0:
		return adapter.Entry{}, false, nil
	case 1:
		return c.entry(res.Entries[0]), true, nil
	}
	return adapter.Entry{}, false, fmt.Errorf("%d entries under %s have %s=%s", len(res.Entries), c.cfg.UserBase, c.cfg.UserAttr, uid)
}

func (c *Client) entry(e *ldap.Entry) adapter.Entry {
	return adapter.Entry{UID: e.GetEqualFoldAttributeValue(c.cfg.UserAttr), Account: e.GetEqualFoldAttributeValue(c.cfg.AccountAttr)}
}

// Group lists the user entries among a group's members: member and uniqueMember (DNs, as groupOfNames and
// groupOfUniqueNames have them) and memberUid (uids, as posixGroup has them). Members that are not user entries,
// such as nested groups, are left out.
func (c *Client) Group(ctx context.Context, group string) ([]adapter.Entry, bool, error) {
	conn, err := c.connect(ctx)
	if err != nil {
		return nil, false, err
	}
	defer conn.Close()
	res, err := conn.Search(ldap.NewSearchRequest(c.cfg.GroupBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 0, false,
		fmt.Sprintf("(%s=%s)", c.cfg.GroupAttr, ldap.EscapeFilter(group)), []string{"member", "uniqueMember", "memberUid"}, nil))
	if err != nil {
		return nil, false, fmt.Errorf("searching for group %s: %w", group, err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, false, nil
	case 1:
	default:
		return nil, false, fmt.Errorf("%d entries under %s have %s=%s", len(res.Entries), c.cfg.GroupBase, c.cfg.GroupAttr, group)
	}
	g := res.Entries[0]
	var out []adapter.Entry
	seen := map[string]bool{}
	for _, dn := range append(g.GetEqualFoldAttributeValues("member"), g.GetEqualFoldAttributeValues("uniqueMember")...) {
		if seen[strings.ToLower(dn)] {
			continue
		}
		seen[strings.ToLower(dn)] = true
		r, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)", []string{c.cfg.UserAttr, c.cfg.AccountAttr}, nil))
		if err != nil {
			if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
				continue // a member whose entry is gone
			}
			return nil, false, fmt.Errorf("reading member %s: %w", dn, err)
		}
		for _, e := range r.Entries {
			if ent := c.entry(e); ent.UID != "" {
				out = append(out, ent)
			}
		}
	}
	for _, uid := range g.GetEqualFoldAttributeValues("memberUid") {
		if seen["uid:"+uid] {
			continue
		}
		seen["uid:"+uid] = true
		e, ok, err := c.user(conn, uid)
		if err != nil {
			return nil, false, err
		}
		if ok {
			out = append(out, e)
		}
	}
	return out, true, nil
}
