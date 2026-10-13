// Package ppapi is the small part of the Paperless-ngx REST API the Paperless adapter uses (API version 9, Paperless
// 2.x). The login is a Paperless API token of a user made for the adapter, with permission to add documents and to
// view documents, tags, correspondents, document types and tasks, and nothing else. It stays in the adapter's secrets
// directory; agents never see it.
//
// Every request here is built by the client from scratch. Nothing from an agent's request (headers in particular) is
// ever forwarded: a Paperless that trusts a remote-user header (PAPERLESS_ENABLE_HTTP_REMOTE_USER) would honour it.
package ppapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrNotFound: Paperless has no such object, or the adapter's user may not see it.
var ErrNotFound = errors.New("not found in Paperless")

// ErrUnauthorized: Paperless rejected the adapter's token, or the user lacks the permission.
var ErrUnauthorized = errors.New("Paperless rejected the adapter's token")

// Named is a tag, correspondent or document type.
type Named struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Document is what Paperless returns for one document. Content is present only when asked for.
type Document struct {
	ID                  int    `json:"id"`
	Title               string `json:"title"`
	Correspondent       *int   `json:"correspondent"`
	DocumentType        *int   `json:"document_type"`
	Tags                []int  `json:"tags"`
	Created             string `json:"created"`
	Added               string `json:"added"`
	ArchiveSerialNumber *int   `json:"archive_serial_number"`
	OriginalFileName    string `json:"original_file_name"`
	PageCount           *int   `json:"page_count"`
	Content             string `json:"content,omitempty"`
}

// Task is one consumption task (an upload in progress or finished).
type Task struct {
	TaskID          string `json:"task_id"`
	Status          string `json:"status"` // PENDING, STARTED, SUCCESS, FAILURE
	Result          string `json:"result"`
	TaskFileName    string `json:"task_file_name"`
	RelatedDocument DocID  `json:"related_document"` // the document id once SUCCESS; 0 before
}

// DocID is a document id as Paperless serializes it in a task: a number in current releases, a string in older
// ones, null while the task runs.
type DocID int

func (d *DocID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*d = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fmt.Errorf("related_document %q: %w", s, err)
	}
	*d = DocID(n)
	return nil
}

const (
	TaskSuccess = "SUCCESS"
	TaskFailure = "FAILURE"
)

// Page is one page of a document list.
type Page struct {
	Count   int        `json:"count"`
	Next    *string    `json:"next"`
	Results []Document `json:"results"`
}

// Upload is what goes with the file.
type Upload struct {
	FileName            string
	Title               string
	Created             string // YYYY-MM-DD
	Correspondent       int    // 0: none
	DocumentType        int    // 0: none
	Tags                []int
	ArchiveSerialNumber int // 0: none
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

// New returns a client for base (e.g. http://paperless:8000). hc may be nil.
func New(base, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 2 * time.Minute}
	}
	return &Client{base: strings.TrimRight(base, "/"), token: token, http: hc}
}

const maxJSON = 32 << 20

// DocumentFields is what a listing carries: never the content.
const DocumentFields = "id,title,correspondent,document_type,tags,created,added,archive_serial_number,original_file_name,page_count"

func (c *Client) req(ctx context.Context, method, path string, q url.Values, body io.Reader, ctype string) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Token "+c.token)
	r.Header.Set("Accept", "application/json; version=9")
	if ctype != "" {
		r.Header.Set("Content-Type", ctype)
	}
	resp, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: 401 on %s %s (the token is not one Paperless knows)", ErrUnauthorized, method, path)
	case http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("%w: 403 on %s %s (the adapter's user lacks a permission for it)", ErrUnauthorized, method, path)
	case http.StatusNotFound:
		resp.Body.Close()
		return nil, ErrNotFound
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		return nil, fmt.Errorf("Paperless: %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

func (c *Client) getJSON(ctx context.Context, path string, q url.Values, out any) error {
	resp, err := c.req(ctx, http.MethodGet, path, q, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(io.LimitReader(resp.Body, maxJSON)).Decode(out)
}

// all reads every page of a list of named objects.
func (c *Client) all(ctx context.Context, path string) ([]Named, error) {
	var out []Named
	q := url.Values{"page_size": {"1000"}, "fields": {"id,name"}, "ordering": {"name"}}
	for page := 1; ; page++ {
		q.Set("page", strconv.Itoa(page))
		var p struct {
			Next    *string `json:"next"`
			Results []Named `json:"results"`
		}
		if err := c.getJSON(ctx, path, q, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Results...)
		if p.Next == nil || len(p.Results) == 0 {
			return out, nil
		}
	}
}

func (c *Client) Tags(ctx context.Context) ([]Named, error) { return c.all(ctx, "/api/tags/") }
func (c *Client) Correspondents(ctx context.Context) ([]Named, error) {
	return c.all(ctx, "/api/correspondents/")
}
func (c *Client) DocumentTypes(ctx context.Context) ([]Named, error) {
	return c.all(ctx, "/api/document_types/")
}

// Documents lists documents matching q (Paperless's own filter parameters), without content.
func (c *Client) Documents(ctx context.Context, q url.Values) (Page, error) {
	q = clone(q)
	q.Set("fields", DocumentFields)
	var p Page
	err := c.getJSON(ctx, "/api/documents/", q, &p)
	return p, err
}

// Document reads one document, with its content.
func (c *Client) Document(ctx context.Context, id int) (Document, error) {
	var d Document
	err := c.getJSON(ctx, "/api/documents/"+strconv.Itoa(id)+"/", url.Values{"fields": {DocumentFields + ",content"}}, &d)
	return d, err
}

// Download returns the document's original file: the body (which the caller closes), its content type and the file
// name Paperless gives it.
func (c *Client) Download(ctx context.Context, id int) (body io.ReadCloser, ctype, name string, err error) {
	resp, err := c.req(ctx, http.MethodGet, "/api/documents/"+strconv.Itoa(id)+"/download/", url.Values{"original": {"true"}}, nil, "")
	if err != nil {
		return nil, "", "", err
	}
	if _, params, err := mime.ParseMediaType(resp.Header.Get("Content-Disposition")); err == nil {
		name = params["filename"]
	}
	return resp.Body, resp.Header.Get("Content-Type"), name, nil
}

// Post uploads a file for consumption and returns the task id.
func (c *Client) Post(ctx context.Context, up Upload, file io.Reader) (string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("document", up.FileName)
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(fw, file); err != nil {
		return "", err
	}
	field := func(k, v string) {
		if v != "" {
			_ = w.WriteField(k, v)
		}
	}
	field("title", up.Title)
	field("created", up.Created)
	if up.Correspondent > 0 {
		field("correspondent", strconv.Itoa(up.Correspondent))
	}
	if up.DocumentType > 0 {
		field("document_type", strconv.Itoa(up.DocumentType))
	}
	for _, t := range up.Tags {
		field("tags", strconv.Itoa(t))
	}
	if up.ArchiveSerialNumber > 0 {
		field("archive_serial_number", strconv.Itoa(up.ArchiveSerialNumber))
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	resp, err := c.req(ctx, http.MethodPost, "/api/documents/post_document/", nil, &buf, w.FormDataContentType())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var id string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&id); err != nil {
		return "", fmt.Errorf("Paperless: task id: %w", err)
	}
	if id == "" {
		return "", errors.New("Paperless: empty task id")
	}
	return id, nil
}

// Task reads one consumption task by its id. ok false: Paperless has no such task (yet).
func (c *Client) Task(ctx context.Context, taskID string) (Task, bool, error) {
	var ts []Task
	if err := c.getJSON(ctx, "/api/tasks/", url.Values{"task_id": {taskID}}, &ts); err != nil {
		return Task{}, false, err
	}
	for _, t := range ts {
		if t.TaskID == taskID {
			return t, true, nil
		}
	}
	return Task{}, false, nil
}

func clone(q url.Values) url.Values {
	out := url.Values{}
	for k, v := range q {
		out[k] = append([]string(nil), v...)
	}
	return out
}
