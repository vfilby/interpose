package paperless

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapters/paperless/ppapi"
	"github.com/vfilby/interpose/internal/protocol"
)

// fakePaperless is the part of Paperless's API the client uses, over real HTTP, with the token-only auth the
// adapter relies on.
type fakePaperless struct {
	t  *testing.T
	mu sync.Mutex

	docs  []ppapi.Document
	text  map[int]string // content by id
	tasks map[string]ppapi.Task
	next  int
	// consume: what the next upload becomes (nil: a new document with the given title)
	fail string

	calls []string
}

var (
	fakeTags  = []ppapi.Named{{ID: 1, Name: "receipt"}, {ID: 2, Name: "2026"}, {ID: 3, Name: "medical"}}
	fakeCorrs = []ppapi.Named{{ID: 10, Name: "Insurance Co"}, {ID: 11, Name: "Hydro"}}
	fakeTypes = []ppapi.Named{{ID: 20, Name: "Invoice"}, {ID: 21, Name: "Letter"}}
)

func ip(n int) *int { return &n }

func newFake(t *testing.T) *fakePaperless {
	f := &fakePaperless{t: t, text: map[int]string{}, tasks: map[string]ppapi.Task{}, next: 100}
	f.docs = []ppapi.Document{
		{ID: 1, Title: "Policy renewal", Correspondent: ip(10), DocumentType: ip(21), Tags: []int{2}, Created: "2026-01-05"},
		{ID: 2, Title: "Claim form", Correspondent: ip(10), DocumentType: ip(21), Tags: []int{2, 3}, Created: "2026-03-01"},
		{ID: 3, Title: "Hydro bill March", Correspondent: ip(11), DocumentType: ip(20), Tags: []int{1, 2}, Created: "2026-03-10"},
		{ID: 4, Title: "Hydro bill April", Correspondent: ip(11), DocumentType: ip(20), Tags: []int{1, 2}, Created: "2026-04-10"},
	}
	f.text[1], f.text[2], f.text[3], f.text[4] = "your policy renews", "claim for the visit", "hydro march 42.00", "hydro april 40.00"
	return f
}

func (f *fakePaperless) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("Authorization") != "Token pp-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("Remote-User") != "" || r.Header.Get("X-Lease") != "" {
		f.t.Errorf("client header forwarded to Paperless: %v", r.Header)
	}
	list := func(ns []ppapi.Named) {
		json.NewEncoder(w).Encode(map[string]any{"count": len(ns), "next": nil, "results": ns})
	}
	q := r.URL.Query()
	switch {
	case r.Method == "GET" && r.URL.Path == "/api/tags/":
		list(fakeTags)
	case r.Method == "GET" && r.URL.Path == "/api/correspondents/":
		list(fakeCorrs)
	case r.Method == "GET" && r.URL.Path == "/api/document_types/":
		list(fakeTypes)
	case r.Method == "GET" && r.URL.Path == "/api/documents/":
		var out []ppapi.Document
		for _, d := range f.docs {
			if f.match(d, q) {
				c := d
				c.Content = ""
				out = append(out, c)
			}
		}
		if out == nil {
			out = []ppapi.Document{}
		}
		json.NewEncoder(w).Encode(map[string]any{"count": len(out), "next": nil, "results": out})
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/documents/") && strings.HasSuffix(r.URL.Path, "/download/"):
		id, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/documents/"), "/download/"))
		if _, ok := f.text[id]; !ok {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="doc-%d.pdf"`, id))
		fmt.Fprintf(w, "%%PDF %d", id)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/documents/"):
		id, _ := strconv.Atoi(strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/documents/"), "/"))
		for _, d := range f.docs {
			if d.ID == id {
				d.Content = f.text[id]
				json.NewEncoder(w).Encode(d)
				return
			}
		}
		w.WriteHeader(404)
	case r.Method == "POST" && r.URL.Path == "/api/documents/post_document/":
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			w.WriteHeader(400)
			return
		}
		fh, _, err := r.FormFile("document")
		if err != nil {
			w.WriteHeader(400)
			return
		}
		fh.Close()
		id := fmt.Sprintf("task-%d", len(f.tasks)+1)
		if f.fail != "" {
			f.tasks[id] = ppapi.Task{TaskID: id, Status: "FAILURE", Result: f.fail}
		} else {
			f.next++
			d := ppapi.Document{ID: f.next, Title: r.FormValue("title"), Created: r.FormValue("created")}
			if c := r.FormValue("correspondent"); c != "" {
				n, _ := strconv.Atoi(c)
				d.Correspondent = &n
			}
			for _, t := range r.MultipartForm.Value["tags"] {
				n, _ := strconv.Atoi(t)
				d.Tags = append(d.Tags, n)
			}
			f.docs = append(f.docs, d)
			f.text[d.ID] = "uploaded"
			// One poll sees it pending, then done.
			f.tasks[id] = ppapi.Task{TaskID: id, Status: "PENDING", TaskFileName: r.FormValue("title")}
			go func() {
				time.Sleep(50 * time.Millisecond)
				f.mu.Lock()
				f.tasks[id] = ppapi.Task{TaskID: id, Status: "SUCCESS", RelatedDocument: ppapi.DocID(d.ID), TaskFileName: d.Title}
				f.mu.Unlock()
			}()
		}
		json.NewEncoder(w).Encode(id)
	case r.Method == "GET" && r.URL.Path == "/api/tasks/":
		var out []ppapi.Task
		if t, ok := f.tasks[q.Get("task_id")]; ok {
			out = append(out, t)
		}
		if out == nil {
			out = []ppapi.Task{}
		}
		json.NewEncoder(w).Encode(out)
	default:
		w.WriteHeader(404)
	}
}

// match applies the filter parameters the gateway uses.
func (f *fakePaperless) match(d ppapi.Document, q url.Values) bool {
	if v := q.Get("correspondent__id"); v != "" && (d.Correspondent == nil || strconv.Itoa(*d.Correspondent) != v) {
		return false
	}
	if v := q.Get("document_type__id"); v != "" && (d.DocumentType == nil || strconv.Itoa(*d.DocumentType) != v) {
		return false
	}
	if v := q.Get("tags__id__all"); v != "" {
		for _, s := range strings.Split(v, ",") {
			n, _ := strconv.Atoi(s)
			if !slices.Contains(d.Tags, n) {
				return false
			}
		}
	}
	if v := q.Get("id__in"); v != "" {
		ok := false
		for _, s := range strings.Split(v, ",") {
			if n, _ := strconv.Atoi(s); n == d.ID {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if v := q.Get("query"); v != "" {
		// Good enough for tests: every bare word must appear in title or content.
		for _, word := range strings.Fields(strings.NewReplacer("(", "", ")", "", "AND", "").Replace(v)) {
			hay := strings.ToLower(d.Title + " " + f.text[d.ID])
			if !strings.Contains(hay, strings.ToLower(word)) {
				return false
			}
		}
	}
	return true
}

type harness struct {
	t     *testing.T
	fake  *fakePaperless
	gw    *Gateway
	src   *Source
	srv   *httptest.Server
	token string
	clock time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, fake: newFake(t), clock: time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)}
	pp := httptest.NewServer(h.fake)
	t.Cleanup(pp.Close)
	now := func() time.Time { return h.clock }
	store, err := OpenStore(filepath.Join(t.TempDir(), "leases.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	agents, err := LoadAgents(filepath.Join(t.TempDir(), "agents.json"))
	if err != nil {
		t.Fatal(err)
	}
	h.token, err = agents.Add("maggy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agents.Add("jeeves"); err != nil {
		t.Fatal(err)
	}
	h.gw = &Gateway{PP: ppapi.New(pp.URL, "pp-secret", nil), Store: store, Agents: agents, PublicURL: "https://paperless.home.example/",
		Now: now, MaxWait: 2 * time.Second, UploadWait: time.Second}
	h.src = &Source{Store: store}
	h.srv = httptest.NewServer(h.gw)
	t.Cleanup(h.srv.Close)
	return h
}

// do sends a request as the agent, with lease (if any), and returns the status and the decoded JSON body.
func (h *harness) do(method, path string, body io.Reader, ctype, lease string) (int, map[string]any, []byte) {
	h.t.Helper()
	r, _ := http.NewRequest(method, h.srv.URL+path, body)
	r.Header.Set("Authorization", "Bearer "+h.token)
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	if lease != "" {
		r.Header.Set("X-Lease", lease)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, raw
}

func (h *harness) ask(scope string, extra string) string {
	h.t.Helper()
	code, out, raw := h.do("POST", "/v1/leases", strings.NewReader(`{"scope":`+scope+`,"reason":"tests"`+extra+`}`), "application/json", "")
	if code != 202 {
		h.t.Fatalf("ask lease: %d %s", code, raw)
	}
	if out["status"] != StatusPending {
		h.t.Fatalf("new lease: %v", out)
	}
	return out["id"].(string)
}

func (h *harness) approve(id string) {
	h.t.Helper()
	it, ok, err := h.src.Current(context.Background(), id)
	if err != nil || !ok {
		h.t.Fatalf("current %s: %v %v", id, ok, err)
	}
	if it.Key != id || it.Shape != protocol.ShapeLease || it.Kind != Kind {
		h.t.Fatalf("item: %+v", it)
	}
	if err := h.src.Approve(context.Background(), id); err != nil {
		h.t.Fatal(err)
	}
}

func TestAuth(t *testing.T) {
	h := newHarness(t)
	for _, auth := range []string{"", "Bearer nope", "Token " + h.token} {
		r, _ := http.NewRequest("GET", h.srv.URL+"/v1/tags", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Errorf("auth %q: %d", auth, resp.StatusCode)
		}
	}
	if code, _, raw := h.do("GET", "/v1/tags", nil, "", ""); code != 200 || !strings.Contains(string(raw), "receipt") {
		t.Errorf("tags: %d %s", code, raw)
	}
	resp, err := http.Get(h.srv.URL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Errorf("healthz: %v %v", resp, err)
	}
}

func upload(t *testing.T, h *harness, title string, fields map[string]string) (int, map[string]any, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "receipt.pdf")
	io.WriteString(fw, "%PDF fake")
	w.WriteField("title", title)
	for k, v := range fields {
		w.WriteField(k, v)
	}
	w.Close()
	return h.do("POST", "/v1/documents?wait=2s", &buf, w.FormDataContentType(), "")
}

func TestUploadNeedsNoLease(t *testing.T) {
	h := newHarness(t)
	code, out, raw := upload(t, h, "Pharmacy receipt", map[string]string{"correspondent": "insurance co", "tags": "receipt, 2026", "created": "2026-10-01"})
	if code != 201 || out["status"] != "done" {
		t.Fatalf("upload: %d %s", code, raw)
	}
	doc := out["document"].(map[string]any)
	if doc["url"] != "https://paperless.home.example/documents/101/details" || doc["title"] != "Pharmacy receipt" || doc["correspondent"] != "Insurance Co" {
		t.Errorf("document: %v", doc)
	}
	if tags, _ := doc["tags"].([]any); len(tags) != 2 {
		t.Errorf("tags: %v", doc["tags"])
	}
	if _, has := doc["content"]; has {
		t.Errorf("an upload answer must not carry content: %v", doc)
	}

	// Unknown names are refused before anything reaches Paperless.
	code, _, raw = upload(t, h, "x", map[string]string{"tags": "nope"})
	if code != 400 || !strings.Contains(string(raw), "no tag") {
		t.Errorf("bad tag: %d %s", code, raw)
	}
	code, _, raw = upload(t, h, "x", map[string]string{"created": "yesterday"})
	if code != 400 {
		t.Errorf("bad date: %d %s", code, raw)
	}

	// A duplicate names the existing document.
	h.fake.mu.Lock()
	h.fake.fail = "receipt.pdf: Not consuming receipt.pdf: It is a duplicate of Pharmacy receipt (#101)"
	h.fake.mu.Unlock()
	code, out, raw = upload(t, h, "Pharmacy receipt", nil)
	if code != 409 || out["status"] != "duplicate" {
		t.Fatalf("duplicate: %d %s", code, raw)
	}
	if d := out["document"].(map[string]any); d["id"] != float64(101) {
		t.Errorf("duplicate of: %v", d)
	}
	h.fake.mu.Lock()
	h.fake.fail = "something broke"
	h.fake.mu.Unlock()
	if code, out, raw = upload(t, h, "x", nil); code != 422 || out["status"] != "failed" {
		t.Errorf("failed: %d %s", code, raw)
	}
}

func TestUploadStillConsuming(t *testing.T) {
	h := newHarness(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, _ := w.CreateFormFile("file", "slow.pdf")
	io.WriteString(fw, "%PDF")
	w.WriteField("title", "Slow")
	w.Close()
	// wait=0: answer at once, while the task is still pending.
	code, out, raw := h.do("POST", "/v1/documents?wait=0s", &buf, w.FormDataContentType(), "")
	if code != 202 || out["status"] != "pending" {
		t.Fatalf("still consuming: %d %s", code, raw)
	}
	task := out["task"].(string)
	code, out, raw = h.do("GET", "/v1/uploads/"+task+"?wait=2s", nil, "", "")
	if code != 200 || out["status"] != "done" {
		t.Fatalf("poll: %d %s", code, raw)
	}
}

func TestReadNeedsAnApprovedLease(t *testing.T) {
	h := newHarness(t)
	if code, _, raw := h.do("GET", "/v1/documents?q=hydro", nil, "", ""); code != 403 {
		t.Errorf("no lease: %d %s", code, raw)
	}
	id := h.ask(`{"correspondent":"Hydro"}`, `,"duration":"2h","max_documents":1`)
	if code, _, raw := h.do("GET", "/v1/documents?q=hydro", nil, "", id); code != 403 {
		t.Errorf("pending lease: %d %s", code, raw)
	}
	// The phone sees the facts from the store, not from the agent's words.
	items, err := h.src.Pending(context.Background())
	if err != nil || len(items) != 1 {
		t.Fatalf("pending: %v %v", items, err)
	}
	it := items[0]
	if it.Title != "maggy wants to read Paperless: Correspondent: Hydro" || it.Requester != "maggy" || it.Risk != protocol.RiskNormal {
		t.Errorf("item: %+v", it)
	}
	if it.Lease == nil || it.Lease.DurationS != 7200 || it.Lease.MaxUses != 1 {
		t.Errorf("lease: %+v", it.Lease)
	}
	want := []string{"Agent=maggy", "Correspondent=Hydro", "Duration=2h", "Documents=up to 1"}
	var got []string
	for _, f := range it.Facts {
		got = append(got, f.Label+"="+f.Value)
	}
	if !slices.Equal(got, want) {
		t.Errorf("facts: %v, want %v", got, want)
	}

	// Waiting for the decision returns as soon as it is made.
	done := make(chan map[string]any, 1)
	go func() {
		_, out, _ := h.do("GET", "/v1/leases/"+id+"?wait=2s", nil, "", "")
		done <- out
	}()
	time.Sleep(100 * time.Millisecond)
	h.approve(id)
	select {
	case out := <-done:
		if out["status"] != StatusApproved {
			t.Errorf("after approval: %v", out)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wait did not return")
	}
	if _, ok, _ := h.src.Current(context.Background(), id); ok {
		t.Error("an approved lease is still pending to the core")
	}

	// Search within the scope: Hydro only, even when asking for everything.
	code, out, raw := h.do("GET", "/v1/documents?q=", nil, "", id)
	if code != 200 || out["count"] != float64(2) {
		t.Fatalf("search: %d %s", code, raw)
	}
	for _, d := range out["results"].([]any) {
		m := d.(map[string]any)
		if m["correspondent"] != "Hydro" {
			t.Errorf("outside scope: %v", m)
		}
		if _, has := m["content"]; has {
			t.Errorf("a listing must not carry content: %v", m)
		}
	}
	if code, _, raw := h.do("GET", "/v1/documents?correspondent=Insurance%20Co", nil, "", id); code != 400 {
		t.Errorf("widening the scope: %d %s", code, raw)
	}
	// Narrowing is fine.
	if code, out, raw := h.do("GET", "/v1/documents?q=april", nil, "", id); code != 200 || out["count"] != float64(1) {
		t.Errorf("narrow search: %d %s", code, raw)
	}

	// A document outside the scope is refused and costs nothing; one inside is read and charged.
	if code, _, raw := h.do("GET", "/v1/documents/1", nil, "", id); code != 403 {
		t.Errorf("outside: %d %s", code, raw)
	}
	code, out, raw = h.do("GET", "/v1/documents/3", nil, "", id)
	if code != 200 || out["content"] != "hydro march 42.00" || out["url"] != "https://paperless.home.example/documents/3/details" {
		t.Fatalf("read: %d %s", code, raw)
	}
	// The same document again, and its file: free. A second document: over budget.
	if code, _, raw := h.do("GET", "/v1/documents/3", nil, "", id); code != 200 {
		t.Errorf("re-read: %d %s", code, raw)
	}
	code, _, raw = h.do("GET", "/v1/documents/3/file", nil, "", id)
	if code != 200 || string(raw) != "%PDF 3" {
		t.Errorf("file: %d %q", code, raw)
	}
	if code, _, raw := h.do("GET", "/v1/documents/4", nil, "", id); code != 403 || !strings.Contains(string(raw), "maximum") {
		t.Errorf("over budget: %d %s", code, raw)
	}
	l, _ := h.gw.Store.Get(id)
	if !slices.Equal(l.Read, []int{3}) {
		t.Errorf("read: %v", l.Read)
	}

	// Another agent cannot use it.
	jeeves := newHarnessToken(t, h, "jeeves")
	r, _ := http.NewRequest("GET", h.srv.URL+"/v1/documents/3", nil)
	r.Header.Set("Authorization", "Bearer "+jeeves)
	r.Header.Set("X-Lease", id)
	resp, _ := http.DefaultClient.Do(r)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("another agent's lease: %d", resp.StatusCode)
	}

	// Time passes: the lease ends.
	h.clock = h.clock.Add(3 * time.Hour)
	if code, _, raw := h.do("GET", "/v1/documents/3", nil, "", id); code != 403 || !strings.Contains(string(raw), "expired") {
		t.Errorf("expired: %d %s", code, raw)
	}
	if _, out, _ := h.do("GET", "/v1/leases/"+id, nil, "", ""); out["status"] != StatusExpired {
		t.Errorf("status: %v", out)
	}
}

func newHarnessToken(t *testing.T, h *harness, name string) string {
	t.Helper()
	tok, err := h.gw.Agents.Add(name)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestDenyAndUnscoped(t *testing.T) {
	h := newHarness(t)
	id := h.ask(`{}`, `,"max_documents":0`)
	items, _ := h.src.Pending(context.Background())
	if len(items) != 1 || items[0].Risk != protocol.RiskElevated {
		t.Fatalf("an unscoped lease is elevated: %+v", items)
	}
	var levels []string
	for _, f := range items[0].Facts {
		if f.Level != "" {
			levels = append(levels, f.Label+":"+f.Level)
		}
	}
	if !slices.Equal(levels, []string{"Scope:danger", "Documents:warn"}) {
		t.Errorf("levels: %v", levels)
	}
	if err := h.src.Deny(context.Background(), id, "no"); err != nil {
		t.Fatal(err)
	}
	if err := h.src.Deny(context.Background(), id, "again"); err != adapter.ErrGone {
		t.Errorf("deny twice: %v", err)
	}
	_, out, _ := h.do("GET", "/v1/leases/"+id, nil, "", "")
	if out["status"] != StatusDenied || out["deny_reason"] != "no" {
		t.Errorf("denied: %v", out)
	}
	if code, _, _ := h.do("GET", "/v1/documents/1", nil, "", id); code != 403 {
		t.Errorf("denied lease read: %d", code)
	}

	// An unscoped, approved lease reads anything.
	id = h.ask(`{}`, ``)
	h.approve(id)
	if code, out, raw := h.do("GET", "/v1/documents", nil, "", id); code != 200 || out["count"] != float64(4) {
		t.Errorf("all: %d %s", code, raw)
	}
	if code, _, _ := h.do("GET", "/v1/documents/1", nil, "", id); code != 200 {
		t.Errorf("read: %d", code)
	}
}

func TestScopeShapes(t *testing.T) {
	h := newHarness(t)
	// Tags and a document type together; the search query adds to the scope's own.
	id := h.ask(`{"tags":["receipt","2026"],"document_type":"invoice","query":"hydro"}`, ``)
	h.approve(id)
	l, _ := h.gw.Store.Get(id)
	if l.Scope.Summary() != "Document type: Invoice; Tags: receipt, 2026; Search: hydro" {
		t.Errorf("summary: %q", l.Scope.Summary())
	}
	if code, out, raw := h.do("GET", "/v1/documents?q=march", nil, "", id); code != 200 || out["count"] != float64(1) {
		t.Errorf("search: %d %s", code, raw)
	}
	// Explicit documents.
	id = h.ask(`{"documents":[2,4]}`, ``)
	h.approve(id)
	if code, _, _ := h.do("GET", "/v1/documents/2", nil, "", id); code != 200 {
		t.Errorf("listed: %d", code)
	}
	if code, _, _ := h.do("GET", "/v1/documents/3", nil, "", id); code != 403 {
		t.Errorf("unlisted: %d", code)
	}
	// Bad asks.
	for _, body := range []string{`{"scope":{"correspondent":"nobody"},"reason":"x"}`, `{"scope":{},"reason":""}`,
		`{"scope":{},"reason":"x","duration":"48h"}`, `{"scope":{},"reason":"x","duration":"soon"}`, `{"scope":{"documents":[0]},"reason":"x"}`} {
		if code, _, raw := h.do("POST", "/v1/leases", strings.NewReader(body), "application/json", ""); code != 400 {
			t.Errorf("%s: %d %s", body, code, raw)
		}
	}
}

func TestStorePersists(t *testing.T) {
	dir := t.TempDir()
	clock := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	s, err := OpenStore(filepath.Join(dir, "leases.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	l := s.Add("maggy", Scope{Correspondent: "Hydro", CorrespondentID: 11}, time.Hour, 5, "why")
	if err := s.Approve(l.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Use("maggy", l.ID, 7); err != nil {
		t.Fatal(err)
	}
	old := s.Add("maggy", Scope{}, time.Hour, 5, "old")
	if err := s.Deny(old.ID, "no"); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(filepath.Join(dir, "leases.json"), now)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(l.ID)
	if !ok || got.Status != StatusApproved || !slices.Equal(got.Read, []int{7}) || got.Scope.CorrespondentID != 11 {
		t.Errorf("reloaded: %+v", got)
	}
	if _, ok := s2.Get(old.ID); !ok {
		t.Error("a fresh denial is kept")
	}
	// Finished leases are forgotten after a week; a live one is not.
	clock = clock.Add(8 * 24 * time.Hour)
	s2.Add("jeeves", Scope{}, time.Hour, 1, "trigger a save")
	if _, ok := s2.Get(old.ID); ok {
		t.Error("an old denial is still kept")
	}
	if _, err := s2.Use("maggy", l.ID, 7); err != ErrNoLease {
		t.Errorf("after a week: %v", err)
	}
}

func TestAgents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agents.json")
	a, err := LoadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Add("Maggy!"); err != ErrAgentName {
		t.Errorf("bad name: %v", err)
	}
	tok, err := a.Add("maggy")
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadAgents(path)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := b.Lookup(tok); !ok || n != "maggy" {
		t.Errorf("lookup: %q %v", n, ok)
	}
	if _, ok := b.Lookup(tok + "x"); ok {
		t.Error("wrong token found")
	}
	if _, ok := b.Lookup(""); ok {
		t.Error("empty token found")
	}
	raw, _ := io.ReadAll(mustOpen(t, path))
	if strings.Contains(string(raw), tok) {
		t.Error("the token itself is on disk")
	}
	if err := b.Remove("maggy"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Lookup(tok); ok {
		t.Error("removed agent still found")
	}
}

func mustOpen(t *testing.T, path string) io.Reader {
	t.Helper()
	f, err := http.Dir(filepath.Dir(path)).Open(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
