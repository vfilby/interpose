package paperless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vfilby/interpose/adapters/paperless/ppapi"
	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
)

// Paperless is what the gateway needs from ppapi.Client.
type Paperless interface {
	Tags(ctx context.Context) ([]ppapi.Named, error)
	Correspondents(ctx context.Context) ([]ppapi.Named, error)
	DocumentTypes(ctx context.Context) ([]ppapi.Named, error)
	Documents(ctx context.Context, q url.Values) (ppapi.Page, error)
	Document(ctx context.Context, id int) (ppapi.Document, error)
	Download(ctx context.Context, id int) (io.ReadCloser, string, string, error)
	Post(ctx context.Context, up ppapi.Upload, file io.Reader) (string, error)
	Task(ctx context.Context, taskID string) (ppapi.Task, bool, error)
}

// Gateway is the HTTP API agents use. It is an http.Handler; serve it behind TLS and whatever network limits the
// deployment wants (it checks bearer tokens, nothing else about the caller).
//
//	GET  /healthz
//	GET  /v1/tags | /v1/correspondents | /v1/document_types     names, for filing and for asking well-scoped leases
//	POST /v1/documents                                           upload (multipart: file, title, created, correspondent,
//	                                                             document_type, tags, asn); ?wait= for the result
//	GET  /v1/uploads/{task}                                      the result of an upload still consuming; ?wait=
//	POST /v1/leases                                              ask for a read lease (JSON: scope, duration,
//	                                                             max_documents, reason)
//	GET  /v1/leases | /v1/leases/{id}                            this agent's leases; ?wait= blocks while pending
//	GET  /v1/documents?q=...                                     search within a lease (header X-Lease or ?lease=)
//	GET  /v1/documents/{id}                                      one document with its text (charged to the lease)
//	GET  /v1/documents/{id}/file                                 its original file (the same document, not charged again)
type Gateway struct {
	PP     Paperless
	Store  *Store
	Agents *Agents
	// PublicURL is Paperless as people open it (https://paperless.home.example): links in answers point there.
	PublicURL string
	// Access is where every call that touched a document is recorded. nil: not recorded.
	Access *audit.Log
	Log    *slog.Logger

	// Limits. Zero: the defaults below.
	MaxUpload      int64         // bytes per upload
	DefaultLease   time.Duration // when the agent gives no duration
	MaxLease       time.Duration // the longest lease an agent may ask for
	DefaultMaxDocs int           // when the agent gives no max_documents
	MaxWait        time.Duration // the longest ?wait=
	UploadWait     time.Duration // default ?wait= on an upload
	NamesTTL       time.Duration // how long tag/correspondent/type names are cached
	Now            func() time.Time
	mux            *http.ServeMux
	once           sync.Once
	namesMu        sync.Mutex
	names          map[string]names
}

const (
	defaultMaxUpload   = 100 << 20
	defaultLease       = time.Hour
	defaultMaxLease    = 24 * time.Hour
	defaultMaxDocs     = 20
	defaultMaxWait     = 2 * time.Minute
	defaultUploadWait  = 90 * time.Second
	defaultNamesTTL    = time.Minute
	maxPageSize        = 100
	maxScopeDocuments  = 200
	maxSearchQuery     = 512
	maxTitle           = 256
	maxUploadFileName  = 256
	maxAgentListLeases = 100
)

func (g *Gateway) now() time.Time {
	if g.Now != nil {
		return g.Now()
	}
	return time.Now()
}

func (g *Gateway) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

func (g *Gateway) init() {
	if g.MaxUpload == 0 {
		g.MaxUpload = defaultMaxUpload
	}
	if g.DefaultLease == 0 {
		g.DefaultLease = defaultLease
	}
	if g.MaxLease == 0 {
		g.MaxLease = defaultMaxLease
	}
	if g.DefaultMaxDocs == 0 {
		g.DefaultMaxDocs = defaultMaxDocs
	}
	if g.MaxWait == 0 {
		g.MaxWait = defaultMaxWait
	}
	if g.UploadWait == 0 {
		g.UploadWait = defaultUploadWait
	}
	if g.NamesTTL == 0 {
		g.NamesTTL = defaultNamesTTL
	}
	g.names = map[string]names{}
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	m.Handle("GET /v1/tags", g.auth(g.named("tags")))
	m.Handle("GET /v1/correspondents", g.auth(g.named("correspondents")))
	m.Handle("GET /v1/document_types", g.auth(g.named("document_types")))
	m.Handle("POST /v1/documents", g.auth(g.upload))
	m.Handle("GET /v1/uploads/{task}", g.auth(g.uploadResult))
	m.Handle("POST /v1/leases", g.auth(g.askLease))
	m.Handle("GET /v1/leases", g.auth(g.listLeases))
	m.Handle("GET /v1/leases/{id}", g.auth(g.getLease))
	m.Handle("GET /v1/documents", g.auth(g.search))
	m.Handle("GET /v1/documents/{id}", g.auth(g.document))
	m.Handle("GET /v1/documents/{id}/file", g.auth(g.file))
	g.mux = m
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.once.Do(g.init)
	g.mux.ServeHTTP(w, r)
}

// handler is a request by a known agent.
type handler func(w http.ResponseWriter, r *http.Request, agent string)

func (g *Gateway) auth(h handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		agent, found := "", false
		if ok {
			agent, found = g.Agents.Lookup(tok)
		}
		if !found {
			w.Header().Set("WWW-Authenticate", `Bearer realm="paperless-gateway"`)
			g.log().Warn("request refused", "method", r.Method, "path", r.URL.Path, "status", http.StatusUnauthorized, "error", "unknown agent token")
			fail(w, http.StatusUnauthorized, "unknown agent token")
			return
		}
		rec := &statusRecorder{ResponseWriter: w}
		h(rec, r, agent)
		// Every failure an agent sees is in the log too, with what it was told: the agent's report and the log agree.
		if rec.status >= 400 {
			g.log().Warn("request failed", "agent", agent, "method", r.Method, "path", r.URL.Path, "status", rec.status, "error", strings.TrimSpace(rec.body.String()))
		}
	})
}

// statusRecorder remembers the status a handler sent and, for failures, the start of the body.
type statusRecorder struct {
	http.ResponseWriter
	status int
	body   strings.Builder
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	if s.status >= 400 && s.body.Len() < 300 {
		s.body.Write(b[:min(len(b), 300-s.body.Len())])
	}
	return s.ResponseWriter.Write(b)
}

func fail(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	enc.Encode(v)
}

// upstream turns an error from Paperless into a response.
func (g *Gateway) upstream(w http.ResponseWriter, what string, err error) {
	switch {
	case errors.Is(err, ppapi.ErrNotFound):
		fail(w, http.StatusNotFound, what+": not found")
	case errors.Is(err, ppapi.ErrUnauthorized):
		g.log().Error("Paperless refused the adapter's token", "err", err)
		fail(w, http.StatusBadGateway, "Paperless refused the gateway's own login; tell the operator")
	default:
		g.log().Error("Paperless", "what", what, "err", err)
		fail(w, http.StatusBadGateway, what+": Paperless did not answer properly")
	}
}

// record writes one access-log line.
func (g *Gateway) record(event, agent, lease, target, detail string) {
	if g.Access == nil {
		return
	}
	if err := g.Access.Write(audit.Event{Time: g.now(), Event: event, Requester: agent, RequestID: lease, Target: target, Detail: detail}); err != nil {
		g.log().Error("access log", "err", err)
	}
}

// wait reads ?wait= bounded by MaxWait; def when absent.
func (g *Gateway) wait(r *http.Request, def time.Duration) (time.Duration, error) {
	s := r.URL.Query().Get("wait")
	if s == "" {
		return min(def, g.MaxWait), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, errors.New("wait: a duration like 30s or 2m")
	}
	return min(d, g.MaxWait), nil
}

// names: one kind of named object, by id and by lower-cased name.
type names struct {
	fetched time.Time
	list    []ppapi.Named
	byID    map[int]string
	byName  map[string]int
}

func (g *Gateway) lookup(ctx context.Context, kind string, fresh bool) (names, error) {
	g.namesMu.Lock()
	n, ok := g.names[kind]
	g.namesMu.Unlock()
	if ok && !fresh && g.now().Sub(n.fetched) < g.NamesTTL {
		return n, nil
	}
	var list []ppapi.Named
	var err error
	switch kind {
	case "tags":
		list, err = g.PP.Tags(ctx)
	case "correspondents":
		list, err = g.PP.Correspondents(ctx)
	case "document_types":
		list, err = g.PP.DocumentTypes(ctx)
	default:
		panic("names: " + kind)
	}
	if err != nil {
		return names{}, err
	}
	n = names{fetched: g.now(), list: list, byID: map[int]string{}, byName: map[string]int{}}
	for _, x := range list {
		n.byID[x.ID] = x.Name
		n.byName[strings.ToLower(strings.TrimSpace(x.Name))] = x.ID
	}
	g.namesMu.Lock()
	g.names[kind] = n
	g.namesMu.Unlock()
	return n, nil
}

// resolve finds the id of name among kind, refreshing the cache once on a miss. 0: no such name.
func (g *Gateway) resolve(ctx context.Context, kind, name string) (int, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return 0, nil
	}
	n, err := g.lookup(ctx, kind, false)
	if err != nil {
		return 0, err
	}
	if id, ok := n.byName[key]; ok {
		return id, nil
	}
	if n, err = g.lookup(ctx, kind, true); err != nil {
		return 0, err
	}
	return n.byName[key], nil
}

func (g *Gateway) named(kind string) handler {
	return func(w http.ResponseWriter, r *http.Request, _ string) {
		n, err := g.lookup(r.Context(), kind, false)
		if err != nil {
			g.upstream(w, kind, err)
			return
		}
		list := n.list
		if list == nil {
			list = []ppapi.Named{}
		}
		reply(w, http.StatusOK, list)
	}
}

// docView is a document as the gateway shows it: names instead of ids, and a link.
type docView struct {
	ID                  int      `json:"id"`
	Title               string   `json:"title"`
	Correspondent       string   `json:"correspondent,omitempty"`
	DocumentType        string   `json:"document_type,omitempty"`
	Tags                []string `json:"tags"`
	Created             string   `json:"created,omitempty"`
	Added               string   `json:"added,omitempty"`
	ArchiveSerialNumber *int     `json:"archive_serial_number,omitempty"`
	OriginalFileName    string   `json:"original_file_name,omitempty"`
	PageCount           *int     `json:"page_count,omitempty"`
	URL                 string   `json:"url"`
	Content             string   `json:"content,omitempty"`
}

func (g *Gateway) docURL(id int) string {
	return strings.TrimRight(g.PublicURL, "/") + "/documents/" + strconv.Itoa(id) + "/details"
}

func (g *Gateway) view(ctx context.Context, d ppapi.Document) docView {
	v := docView{ID: d.ID, Title: d.Title, Tags: []string{}, Created: d.Created, Added: d.Added, ArchiveSerialNumber: d.ArchiveSerialNumber,
		OriginalFileName: d.OriginalFileName, PageCount: d.PageCount, URL: g.docURL(d.ID), Content: d.Content}
	if d.Correspondent != nil {
		if n, err := g.lookup(ctx, "correspondents", false); err == nil {
			v.Correspondent = n.byID[*d.Correspondent]
		}
	}
	if d.DocumentType != nil {
		if n, err := g.lookup(ctx, "document_types", false); err == nil {
			v.DocumentType = n.byID[*d.DocumentType]
		}
	}
	if len(d.Tags) > 0 {
		if n, err := g.lookup(ctx, "tags", false); err == nil {
			for _, t := range d.Tags {
				if name := n.byID[t]; name != "" {
					v.Tags = append(v.Tags, name)
				}
			}
		}
	}
	return v
}

// ---- uploads

var isoDate = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func (g *Gateway) upload(w http.ResponseWriter, r *http.Request, agent string) {
	wait, err := g.wait(r, g.UploadWait)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.MaxUpload+1<<20)
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		fail(w, http.StatusBadRequest, "multipart form with a `file` part: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail(w, http.StatusBadRequest, "a `file` part is required")
		return
	}
	defer f.Close()
	if hdr.Size > g.MaxUpload {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file larger than %d MiB", g.MaxUpload>>20))
		return
	}
	up := ppapi.Upload{FileName: protocol.CleanText(hdr.Filename, maxUploadFileName), Title: protocol.CleanText(r.FormValue("title"), maxTitle),
		Created: strings.TrimSpace(r.FormValue("created"))}
	if up.FileName == "" {
		up.FileName = "upload"
	}
	if up.Created != "" && !isoDate.MatchString(up.Created) {
		fail(w, http.StatusBadRequest, "created: YYYY-MM-DD")
		return
	}
	ctx := r.Context()
	if c := r.FormValue("correspondent"); c != "" {
		if up.Correspondent, err = g.resolve(ctx, "correspondents", c); err != nil {
			g.upstream(w, "correspondents", err)
			return
		} else if up.Correspondent == 0 {
			fail(w, http.StatusBadRequest, "correspondent: no such name (GET /v1/correspondents lists them)")
			return
		}
	}
	if t := r.FormValue("document_type"); t != "" {
		if up.DocumentType, err = g.resolve(ctx, "document_types", t); err != nil {
			g.upstream(w, "document_types", err)
			return
		} else if up.DocumentType == 0 {
			fail(w, http.StatusBadRequest, "document_type: no such name (GET /v1/document_types lists them)")
			return
		}
	}
	for _, t := range splitNames(r.MultipartForm.Value["tags"]) {
		id, err := g.resolve(ctx, "tags", t)
		if err != nil {
			g.upstream(w, "tags", err)
			return
		}
		if id == 0 {
			fail(w, http.StatusBadRequest, fmt.Sprintf("tags: no tag %q (GET /v1/tags lists them)", t))
			return
		}
		up.Tags = append(up.Tags, id)
	}
	if s := strings.TrimSpace(r.FormValue("asn")); s != "" {
		if up.ArchiveSerialNumber, err = strconv.Atoi(s); err != nil || up.ArchiveSerialNumber <= 0 {
			fail(w, http.StatusBadRequest, "asn: a positive integer")
			return
		}
	}
	task, err := g.PP.Post(ctx, up, f)
	if err != nil {
		g.upstream(w, "upload", err)
		return
	}
	g.record("upload", agent, "", "task:"+task, fmt.Sprintf("%s (%d bytes) title=%q", up.FileName, hdr.Size, up.Title))
	g.log().Info("upload", "agent", agent, "task", task, "file", up.FileName, "bytes", hdr.Size)
	g.taskResult(w, r, agent, task, wait, http.StatusCreated)
}

// splitNames: repeated form values, each possibly comma-separated.
func splitNames(vs []string) []string {
	var out []string
	for _, v := range vs {
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func (g *Gateway) uploadResult(w http.ResponseWriter, r *http.Request, agent string) {
	task := r.PathValue("task")
	if len(task) > 64 || strings.ContainsAny(task, "/?#& ") {
		fail(w, http.StatusBadRequest, "task: a task id from an upload")
		return
	}
	wait, err := g.wait(r, 0)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	g.taskResult(w, r, agent, task, wait, http.StatusOK)
}

var duplicateOf = regexp.MustCompile(`(?i)duplicate.*?#(\d+)`)

// taskResult answers for an upload: done (with the document and its link), still consuming, failed, or a duplicate.
func (g *Gateway) taskResult(w http.ResponseWriter, r *http.Request, agent, task string, wait time.Duration, okCode int) {
	ctx := r.Context()
	deadline := g.now().Add(wait)
	pollEvery := time.Second
	for {
		t, found, err := g.PP.Task(ctx, task)
		if err != nil {
			g.upstream(w, "task", err)
			return
		}
		switch {
		case found && t.Status == ppapi.TaskSuccess:
			id := int(t.RelatedDocument)
			if id <= 0 {
				fail(w, http.StatusBadGateway, "Paperless finished the upload but named no document")
				return
			}
			d, err := g.PP.Document(ctx, id)
			if err != nil {
				// Consumed, but the adapter's user may not see it (a workflow changed its owner): the link still works.
				d = ppapi.Document{ID: id}
			}
			d.Content = ""
			g.record("upload.done", agent, "", "doc:"+strconv.Itoa(id), t.TaskFileName)
			reply(w, okCode, map[string]any{"status": "done", "task": task, "document": g.view(ctx, d)})
			return
		case found && t.Status == ppapi.TaskFailure:
			msg := protocol.CleanText(t.Result, 1024)
			if m := duplicateOf.FindStringSubmatch(t.Result); m != nil {
				id, _ := strconv.Atoi(m[1])
				g.record("upload.duplicate", agent, "", "doc:"+m[1], msg)
				reply(w, http.StatusConflict, map[string]any{"status": "duplicate", "task": task, "error": msg,
					"document": map[string]any{"id": id, "url": g.docURL(id)}})
				return
			}
			g.record("upload.failed", agent, "", "task:"+task, msg)
			reply(w, http.StatusUnprocessableEntity, map[string]any{"status": "failed", "task": task, "error": msg})
			return
		}
		if !g.now().Before(deadline) {
			status := "pending"
			if found && t.Status != "" {
				status = strings.ToLower(t.Status)
			}
			reply(w, http.StatusAccepted, map[string]any{"status": status, "task": task,
				"poll": "/v1/uploads/" + task + "?wait=60s"})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(pollEvery):
		}
		if pollEvery < 5*time.Second {
			pollEvery += time.Second
		}
	}
}

// ---- leases

type leaseAsk struct {
	Scope struct {
		Correspondent string   `json:"correspondent"`
		DocumentType  string   `json:"document_type"`
		Tags          []string `json:"tags"`
		Query         string   `json:"query"`
		Documents     []int    `json:"documents"`
	} `json:"scope"`
	Duration     string `json:"duration"`
	MaxDocuments *int   `json:"max_documents"`
	Reason       string `json:"reason"`
}

func (g *Gateway) askLease(w http.ResponseWriter, r *http.Request, agent string) {
	var ask leaseAsk
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&ask); err != nil {
		fail(w, http.StatusBadRequest, "JSON body: "+err.Error())
		return
	}
	d := g.DefaultLease
	if ask.Duration != "" {
		var err error
		if d, err = time.ParseDuration(ask.Duration); err != nil || d <= 0 {
			fail(w, http.StatusBadRequest, "duration: like 30m, 2h")
			return
		}
	}
	if d > g.MaxLease {
		fail(w, http.StatusBadRequest, fmt.Sprintf("duration: at most %s", human(g.MaxLease)))
		return
	}
	maxDocs := g.DefaultMaxDocs
	if ask.MaxDocuments != nil {
		if *ask.MaxDocuments < 0 {
			fail(w, http.StatusBadRequest, "max_documents: 0 (unlimited) or more")
			return
		}
		maxDocs = *ask.MaxDocuments
	}
	reason := protocol.CleanText(ask.Reason, MaxReason)
	if reason == "" {
		fail(w, http.StatusBadRequest, "reason: say what the documents are for; the person sees it")
		return
	}
	ctx := r.Context()
	sc := Scope{Query: protocol.CleanText(ask.Scope.Query, maxSearchQuery)}
	var err error
	if c := strings.TrimSpace(ask.Scope.Correspondent); c != "" {
		if sc.CorrespondentID, err = g.resolve(ctx, "correspondents", c); err != nil {
			g.upstream(w, "correspondents", err)
			return
		} else if sc.CorrespondentID == 0 {
			fail(w, http.StatusBadRequest, "scope.correspondent: no such name (GET /v1/correspondents lists them)")
			return
		}
		n, _ := g.lookup(ctx, "correspondents", false)
		sc.Correspondent = n.byID[sc.CorrespondentID]
	}
	if t := strings.TrimSpace(ask.Scope.DocumentType); t != "" {
		if sc.DocumentTypeID, err = g.resolve(ctx, "document_types", t); err != nil {
			g.upstream(w, "document_types", err)
			return
		} else if sc.DocumentTypeID == 0 {
			fail(w, http.StatusBadRequest, "scope.document_type: no such name (GET /v1/document_types lists them)")
			return
		}
		n, _ := g.lookup(ctx, "document_types", false)
		sc.DocumentType = n.byID[sc.DocumentTypeID]
	}
	for _, t := range splitNames(ask.Scope.Tags) {
		id, err := g.resolve(ctx, "tags", t)
		if err != nil {
			g.upstream(w, "tags", err)
			return
		}
		if id == 0 {
			fail(w, http.StatusBadRequest, fmt.Sprintf("scope.tags: no tag %q (GET /v1/tags lists them)", t))
			return
		}
		if !slices.Contains(sc.TagIDs, id) {
			n, _ := g.lookup(ctx, "tags", false)
			sc.TagIDs = append(sc.TagIDs, id)
			sc.Tags = append(sc.Tags, n.byID[id])
		}
	}
	if len(ask.Scope.Documents) > maxScopeDocuments {
		fail(w, http.StatusBadRequest, fmt.Sprintf("scope.documents: at most %d", maxScopeDocuments))
		return
	}
	for _, id := range ask.Scope.Documents {
		if id <= 0 {
			fail(w, http.StatusBadRequest, "scope.documents: document ids")
			return
		}
		if !slices.Contains(sc.Documents, id) {
			sc.Documents = append(sc.Documents, id)
		}
	}
	sort.Ints(sc.Documents)
	l := g.Store.Add(agent, sc, d, maxDocs, reason)
	g.record("lease.asked", agent, l.ID, sc.Summary(), fmt.Sprintf("%s, %d documents: %s", human(d), maxDocs, reason))
	g.log().Info("lease asked", "agent", agent, "lease", l.ID, "scope", sc.Summary(), "duration", d)
	reply(w, http.StatusAccepted, leaseView(l))
}

// leaseView is a lease as the agent sees it.
func leaseView(l Lease) map[string]any {
	v := map[string]any{"id": l.ID, "agent": l.Agent, "status": l.Status, "scope": l.Scope.Summary(),
		"duration": human(l.Duration()), "max_documents": l.MaxDocuments, "documents_read": len(l.Read),
		"created": l.Created.UTC().Format(time.RFC3339)}
	if !l.ExpiresAt.IsZero() {
		v["expires_at"] = l.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if l.DenyReason != "" {
		v["deny_reason"] = l.DenyReason
	}
	switch l.Status {
	case StatusPending:
		v["next"] = "wait: GET /v1/leases/" + l.ID + "?wait=60s until status is approved or denied"
	case StatusApproved:
		v["next"] = "read: GET /v1/documents?q=... and GET /v1/documents/{id} with header X-Lease: " + l.ID
	}
	return v
}

func (g *Gateway) listLeases(w http.ResponseWriter, _ *http.Request, agent string) {
	ls := g.Store.ByAgent(agent)
	if len(ls) > maxAgentListLeases {
		ls = ls[len(ls)-maxAgentListLeases:]
	}
	out := make([]map[string]any, 0, len(ls))
	for _, l := range ls {
		out = append(out, leaseView(l))
	}
	reply(w, http.StatusOK, out)
}

func (g *Gateway) getLease(w http.ResponseWriter, r *http.Request, agent string) {
	id := r.PathValue("id")
	l, ok := g.Store.Get(id)
	if !ok || l.Agent != agent {
		fail(w, http.StatusNotFound, "no such lease")
		return
	}
	wait, err := g.wait(r, 0)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if wait > 0 && l.Status == StatusPending {
		ctx, cancel := context.WithTimeout(r.Context(), wait)
		defer cancel()
		l, _ = g.Store.Wait(ctx, id, StatusPending)
	}
	reply(w, http.StatusOK, leaseView(l))
}

// lease checks the agent's lease for a read of doc (0: a search). It answers the request itself when refused.
func (g *Gateway) lease(w http.ResponseWriter, r *http.Request, agent string, doc int) (Lease, bool) {
	id := r.Header.Get("X-Lease")
	if id == "" {
		id = r.URL.Query().Get("lease")
	}
	if id == "" {
		fail(w, http.StatusForbidden, "reading needs an approved lease: POST /v1/leases, then send X-Lease: <id>")
		return Lease{}, false
	}
	l, err := g.Store.Use(agent, id, doc)
	if err != nil {
		code := http.StatusForbidden
		if errors.Is(err, ErrNoLease) || errors.Is(err, ErrNotYours) {
			code = http.StatusNotFound
		}
		g.record("refused", agent, id, "doc:"+strconv.Itoa(doc), err.Error())
		fail(w, code, err.Error())
		return Lease{}, false
	}
	return l, true
}

// inScope reports whether document id is inside the lease's scope, by asking Paperless with the scope's own filter.
func (g *Gateway) inScope(ctx context.Context, l Lease, id int) (bool, error) {
	if l.Scope.Empty() {
		return true, nil
	}
	q := l.Scope.Filter()
	if len(l.Scope.Documents) > 0 {
		if !slices.Contains(l.Scope.Documents, id) {
			return false, nil
		}
	}
	q.Set("id__in", strconv.Itoa(id))
	if l.Scope.Query != "" {
		q.Set("query", l.Scope.Query)
	}
	q.Set("page_size", "1")
	p, err := g.PP.Documents(ctx, q)
	if err != nil {
		return false, err
	}
	for _, d := range p.Results {
		if d.ID == id {
			return true, nil
		}
	}
	return false, nil
}

// ---- reads

func (g *Gateway) search(w http.ResponseWriter, r *http.Request, agent string) {
	l, ok := g.lease(w, r, agent, 0)
	if !ok {
		return
	}
	in := r.URL.Query()
	ctx := r.Context()
	q := l.Scope.Filter()
	// The agent may narrow the scope, never widen it: a field the scope fixes is not for the agent to set.
	fixed := func(field string, set bool) bool {
		if v := in.Get(field); v != "" && set {
			fail(w, http.StatusBadRequest, field+": fixed by the lease's scope")
			return true
		}
		return false
	}
	if fixed("correspondent", l.Scope.CorrespondentID != 0) || fixed("document_type", l.Scope.DocumentTypeID != 0) {
		return
	}
	var err error
	if c := in.Get("correspondent"); c != "" {
		id, err := g.resolve(ctx, "correspondents", c)
		if err != nil {
			g.upstream(w, "correspondents", err)
			return
		}
		if id == 0 {
			fail(w, http.StatusBadRequest, "correspondent: no such name")
			return
		}
		q.Set("correspondent__id", strconv.Itoa(id))
	}
	if t := in.Get("document_type"); t != "" {
		id, err := g.resolve(ctx, "document_types", t)
		if err != nil {
			g.upstream(w, "document_types", err)
			return
		}
		if id == 0 {
			fail(w, http.StatusBadRequest, "document_type: no such name")
			return
		}
		q.Set("document_type__id", strconv.Itoa(id))
	}
	tags := slices.Clone(l.Scope.TagIDs)
	for _, t := range splitNames(in["tags"]) {
		id, err := g.resolve(ctx, "tags", t)
		if err != nil {
			g.upstream(w, "tags", err)
			return
		}
		if id == 0 {
			fail(w, http.StatusBadRequest, fmt.Sprintf("tags: no tag %q", t))
			return
		}
		if !slices.Contains(tags, id) {
			tags = append(tags, id)
		}
	}
	if len(tags) > 0 {
		q.Set("tags__id__all", ints(tags))
	}
	for _, f := range [][2]string{{"created_after", "created__date__gt"}, {"created_before", "created__date__lt"}} {
		if v := in.Get(f[0]); v != "" {
			if !isoDate.MatchString(v) {
				fail(w, http.StatusBadRequest, f[0]+": YYYY-MM-DD")
				return
			}
			q.Set(f[1], v)
		}
	}
	query := protocol.CleanText(in.Get("q"), maxSearchQuery)
	switch {
	case query != "" && l.Scope.Query != "":
		q.Set("query", "("+l.Scope.Query+") AND ("+query+")")
	case query != "":
		q.Set("query", query)
	case l.Scope.Query != "":
		q.Set("query", l.Scope.Query)
	}
	ordering := in.Get("ordering")
	if ordering == "" {
		ordering = "-created"
	}
	if !slices.Contains([]string{"created", "-created", "added", "-added", "title", "-title", "correspondent__name", "-correspondent__name"}, ordering) {
		fail(w, http.StatusBadRequest, "ordering: created, added, title or correspondent__name, with - for descending")
		return
	}
	if q.Get("query") == "" { // a full-text query is ranked; the rest is ordered
		q.Set("ordering", ordering)
	}
	page, size := 1, 25
	if v := in.Get("page"); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 {
			fail(w, http.StatusBadRequest, "page: 1 or more")
			return
		}
	}
	if v := in.Get("page_size"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 || size > maxPageSize {
			fail(w, http.StatusBadRequest, fmt.Sprintf("page_size: 1 to %d", maxPageSize))
			return
		}
	}
	q.Set("page", strconv.Itoa(page))
	q.Set("page_size", strconv.Itoa(size))
	p, err := g.PP.Documents(ctx, q)
	if err != nil {
		if errors.Is(err, ppapi.ErrNotFound) { // a page past the end
			reply(w, http.StatusOK, map[string]any{"count": 0, "page": page, "results": []docView{}})
			return
		}
		g.upstream(w, "search", err)
		return
	}
	out := make([]docView, 0, len(p.Results))
	for _, d := range p.Results {
		d.Content = ""
		out = append(out, g.view(ctx, d))
	}
	g.record("search", agent, l.ID, q.Get("query"), fmt.Sprintf("%d results, page %d", p.Count, page))
	reply(w, http.StatusOK, map[string]any{"count": p.Count, "page": page, "page_size": size, "more": p.Next != nil, "results": out})
}

func (g *Gateway) docID(w http.ResponseWriter, r *http.Request) (int, bool) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil || id <= 0 {
		fail(w, http.StatusBadRequest, "document id")
		return 0, false
	}
	return id, true
}

// reading checks the lease and the scope for one document, charging it to the lease only when it is in scope.
func (g *Gateway) reading(w http.ResponseWriter, r *http.Request, agent string, id int) (Lease, bool) {
	// Scope first, with the lease uncharged: a document outside it must not spend the budget.
	l, ok := g.lease(w, r, agent, 0)
	if !ok {
		return Lease{}, false
	}
	in, err := g.inScope(r.Context(), l, id)
	if err != nil {
		g.upstream(w, "document", err)
		return Lease{}, false
	}
	if !in {
		g.record("refused", agent, l.ID, "doc:"+strconv.Itoa(id), "outside the lease's scope")
		fail(w, http.StatusForbidden, "document is outside the lease's scope (or does not exist)")
		return Lease{}, false
	}
	return g.lease(w, r, agent, id)
}

func (g *Gateway) document(w http.ResponseWriter, r *http.Request, agent string) {
	id, ok := g.docID(w, r)
	if !ok {
		return
	}
	l, ok := g.reading(w, r, agent, id)
	if !ok {
		return
	}
	d, err := g.PP.Document(r.Context(), id)
	if err != nil {
		g.upstream(w, "document", err)
		return
	}
	g.record("read", agent, l.ID, "doc:"+strconv.Itoa(id), d.Title)
	reply(w, http.StatusOK, g.view(r.Context(), d))
}

func (g *Gateway) file(w http.ResponseWriter, r *http.Request, agent string) {
	id, ok := g.docID(w, r)
	if !ok {
		return
	}
	l, ok := g.reading(w, r, agent, id)
	if !ok {
		return
	}
	body, ctype, name, err := g.PP.Download(r.Context(), id)
	if err != nil {
		g.upstream(w, "file", err)
		return
	}
	defer body.Close()
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	if name != "" {
		w.Header().Set("Content-Disposition", "attachment; filename=\""+strings.ReplaceAll(protocol.CleanText(name, maxUploadFileName), `"`, "")+"\"")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	g.record("file", agent, l.ID, "doc:"+strconv.Itoa(id), name)
	w.WriteHeader(http.StatusOK)
	io.Copy(w, body)
}
