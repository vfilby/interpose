// Command interpose-adapter-paperless is the Paperless adapter: the shared adapter command line (adapter/cli,
// `interpose-adapter-paperless key | trust | run`) with the Paperless Source, plus `agent add | remove | list` for the
// tokens agents use at its gateway. It runs beside Paperless and holds a Paperless API token; the gateway it serves
// lets agents add documents freely and read them only within a lease a person granted on a phone.
//
// Paperless settings come from the environment: PAPERLESS_URL, PAPERLESS_TOKEN_FILE, PAPERLESS_PUBLIC_URL, LISTEN,
// DEFAULT_LEASE, MAX_LEASE, MAX_DOCUMENTS, MAX_UPLOAD_MB (deploy/adapter.env.default describes each).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapter/cli"
	"github.com/vfilby/interpose/adapters/paperless"
	"github.com/vfilby/interpose/adapters/paperless/ppapi"
	"github.com/vfilby/interpose/internal/audit"
)

const prog = "interpose-adapter-paperless"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "agent" {
		if err := agentCmd(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
			os.Exit(1)
		}
		return
	}
	cli.Main(prog, cli.Source{Name: "paperless", Flags: func(fs *flag.FlagSet) func(context.Context, *slog.Logger) (adapter.Source, error) {
		listen := fs.String("listen", env("LISTEN", ":8750"), "where the gateway for agents listens")
		return func(ctx context.Context, log *slog.Logger) (adapter.Source, error) {
			dir := "adapter-data"
			if f := fs.Lookup("dir"); f != nil {
				dir = f.Value.String()
			}
			return start(ctx, log, dir, *listen)
		}
	}})
}

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envDuration(k string, def time.Duration) (time.Duration, error) {
	s := env(k, "")
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s: a duration like 2h, not %q", k, s)
	}
	return d, nil
}

func envInt(k string, def int) (int, error) {
	s := env(k, "")
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: a whole number, not %q", k, s)
	}
	return n, nil
}

// start builds the source and serves the gateway until ctx ends.
func start(ctx context.Context, log *slog.Logger, dir, listen string) (adapter.Source, error) {
	// Paperless is reached inside its own stack's network (http://paperless:8000), never across a LAN: plain http
	// to any host is accepted here, unlike the hub URL (adapter.CheckURL), which crosses the network.
	base := env("PAPERLESS_URL", "http://127.0.0.1:8000")
	if u, err := url.Parse(base); err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("PAPERLESS_URL %q: want http://host:port or https://host", base)
	}
	public := env("PAPERLESS_PUBLIC_URL", "")
	if public == "" {
		return nil, errors.New("PAPERLESS_PUBLIC_URL is required: Paperless as people open it, for the links in answers")
	}
	if err := adapter.CheckURL("PAPERLESS_PUBLIC_URL", public); err != nil {
		return nil, err
	}
	tok, err := os.ReadFile(env("PAPERLESS_TOKEN_FILE", "/run/secrets/paperless-token"))
	if err != nil {
		return nil, fmt.Errorf("the Paperless token (PAPERLESS_TOKEN_FILE): %w", err)
	}
	defLease, err := envDuration("DEFAULT_LEASE", time.Hour)
	if err != nil {
		return nil, err
	}
	maxLease, err := envDuration("MAX_LEASE", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	maxDocs, err := envInt("MAX_DOCUMENTS", 20)
	if err != nil {
		return nil, err
	}
	maxMB, err := envInt("MAX_UPLOAD_MB", 100)
	if err != nil {
		return nil, err
	}
	store, err := paperless.OpenStore(filepath.Join(dir, "leases.json"), nil)
	if err != nil {
		return nil, err
	}
	agents, err := paperless.LoadAgents(filepath.Join(dir, "agents.json"))
	if err != nil {
		return nil, err
	}
	if len(agents.Names()) == 0 {
		log.Warn("no agents: nobody can use the gateway (`" + prog + " agent add NAME`)")
	}
	uploads, err := paperless.OpenUploads(filepath.Join(dir, "uploads.json"))
	if err != nil {
		return nil, err
	}
	access, err := audit.OpenRotating(filepath.Join(dir, "access.jsonl"), 64<<20, 8)
	if err != nil {
		return nil, err
	}
	gw := &paperless.Gateway{
		PP:             ppapi.New(base, strings.TrimSpace(string(tok)), nil),
		Store:          store,
		Agents:         agents,
		Uploads:        uploads,
		PublicURL:      public,
		Access:         access,
		Log:            log,
		MaxUpload:      int64(maxMB) << 20,
		DefaultLease:   defLease,
		MaxLease:       maxLease,
		DefaultMaxDocs: maxDocs,
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}
	srv := &http.Server{Handler: gw, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("gateway stopped", "err", err)
		}
	}()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
		_ = access.Close()
	}()
	log.Info("gateway listening", "addr", ln.Addr().String(), "paperless", base, "agents", len(agents.Names()))
	return &paperless.Source{Store: store, Log: log}, nil
}

// agentCmd: agent add NAME | remove NAME | list, each with -dir.
func agentCmd(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: %s agent [-dir D] add NAME | remove NAME | list\n", prog)
	}
	// -dir may come before or after the verb (`agent add -dir=/data NAME` is what people type).
	var flags, rest []string
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			flags = append(flags, a)
		} else {
			rest = append(rest, a)
		}
	}
	_ = fs.Parse(flags)
	if len(rest) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	agents, err := paperless.LoadAgents(filepath.Join(*dir, "agents.json"))
	if err != nil {
		return err
	}
	switch rest[0] {
	case "add":
		if len(rest) != 2 {
			return errors.New("agent add NAME")
		}
		tok, err := agents.Add(rest[1])
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "token for %s (shown once; put it in the agent's credential store):\n", rest[1])
		fmt.Println(tok)
	case "remove":
		if len(rest) != 2 {
			return errors.New("agent remove NAME")
		}
		return agents.Remove(rest[1])
	case "list":
		for _, n := range agents.Names() {
			fmt.Println(n)
		}
	default:
		fs.Usage()
		os.Exit(2)
	}
	return nil
}
