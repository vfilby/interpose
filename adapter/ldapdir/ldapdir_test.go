package ldapdir

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewChecksConfig(t *testing.T) {
	good := Config{URL: "ldaps://ldap.example:636", BindDN: "uid=ro,ou=people,dc=example,dc=org", Password: "x", UserBase: "ou=people,dc=example,dc=org"}
	c, err := New(good)
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.GroupBase != good.UserBase || c.cfg.UserAttr != "uid" || c.cfg.AccountAttr != "interposeAccount" || c.cfg.GroupAttr != "cn" || c.cfg.Timeout != 10*time.Second {
		t.Errorf("defaults: %+v", c.cfg)
	}
	if c.tls.ServerName != "ldap.example" || c.Plain() {
		t.Errorf("tls %+v plain %v", c.tls, c.Plain())
	}
	for name, bad := range map[string]func(c *Config){
		"scheme":   func(c *Config) { c.URL = "https://ldap.example" },
		"no host":  func(c *Config) { c.URL = "ldaps://" },
		"no bind":  func(c *Config) { c.BindDN = "" },
		"no pass":  func(c *Config) { c.Password = "" },
		"no base":  func(c *Config) { c.UserBase = "" },
		"attr":     func(c *Config) { c.AccountAttr = "interpose account" },
		"attr2":    func(c *Config) { c.UserAttr = "uid)(objectClass=*" },
		"ca":       func(c *Config) { c.CAFile = "/nonexistent/ca.pem" },
		"ca empty": func(c *Config) { c.CAFile = os.DevNull },
	} {
		c := good
		bad(&c)
		if _, err := New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	p, _ := New(Config{URL: "ldap://ldap:3890", BindDN: "x", Password: "y", UserBase: "dc=x", Plain: true})
	if !p.Plain() {
		t.Error("Plain with ldap://")
	}
}

// TestLive runs against a real directory when INTERPOSE_LDAP_TEST_URL is set, with INTERPOSE_LDAP_TEST_BIND_DN,
// _PASSWORD, _USER_BASE, _GROUP_BASE, _ACCOUNT_ATTR, and a user INTERPOSE_LDAP_TEST_UID carrying the account
// INTERPOSE_LDAP_TEST_ACCOUNT who is a member of INTERPOSE_LDAP_TEST_GROUP. docs/runbooks/ldap.md shows how to set
// one up with LLDAP in Docker.
func TestLive(t *testing.T) {
	url := os.Getenv("INTERPOSE_LDAP_TEST_URL")
	if url == "" {
		t.Skip("INTERPOSE_LDAP_TEST_URL not set")
	}
	env := func(k, def string) string {
		if v := os.Getenv("INTERPOSE_LDAP_TEST_" + k); v != "" {
			return v
		}
		return def
	}
	c, err := New(Config{URL: url, BindDN: env("BIND_DN", ""), Password: env("PASSWORD", ""), Plain: strings.HasPrefix(url, "ldap://"),
		UserBase: env("USER_BASE", ""), GroupBase: env("GROUP_BASE", ""), AccountAttr: env("ACCOUNT_ATTR", "interposeAccount")})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	uid, account, group := env("UID", "alice"), env("ACCOUNT", ""), env("GROUP", "approvers")

	e, ok, err := c.User(ctx, uid)
	if err != nil || !ok || e.UID != uid || e.Account != account {
		t.Fatalf("User(%s): %+v %v %v", uid, e, ok, err)
	}
	if _, ok, err := c.User(ctx, "no-such-user-"+uid); err != nil || ok {
		t.Fatalf("missing user: ok %v err %v", ok, err)
	}
	if _, ok, err := c.User(ctx, "*"); err != nil || ok {
		t.Fatalf("a filter character is escaped, not interpreted: ok %v err %v", ok, err)
	}

	es, ok, err := c.Group(ctx, group)
	if err != nil || !ok {
		t.Fatalf("Group(%s): %v %v", group, ok, err)
	}
	found := false
	for _, m := range es {
		t.Logf("member %s account %q", m.UID, m.Account)
		found = found || (m.UID == uid && m.Account == account)
	}
	if !found {
		t.Fatalf("%s not among the members of %s with account %q", uid, group, account)
	}
	if _, ok, err := c.Group(ctx, "no-such-group"); err != nil || ok {
		t.Fatalf("missing group: ok %v err %v", ok, err)
	}

	bad, _ := New(Config{URL: url, BindDN: env("BIND_DN", ""), Password: "wrong", Plain: true, UserBase: env("USER_BASE", "")})
	if _, _, err := bad.User(ctx, uid); err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("wrong password: %v", err)
	}
}
