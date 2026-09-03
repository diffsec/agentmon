package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ErrNotModified is returned by a Source whose content has not changed since
// the last Fetch. The Manager keeps the policy it has.
//
// It is a distinct error rather than a nil bundle so a caller cannot mistake
// "unchanged" for "nothing came back", which on a conditional GET is the
// difference between a working poll and one that silently stopped enforcing.
var ErrNotModified = errors.New("policy: not modified")

// Bundle is a policy document and its detached signature.
//
// The two travel together because verification needs both, and because the
// signature does not always arrive as a file: pushed over the wire it is in
// the same message, fetched from a server it is a sibling response. Splitting
// fetch from verify is what lets the same verification run over either.
type Bundle struct {
	// Data is the policy YAML.
	Data []byte
	// Signature is the detached .sig JSON. Nil when the source has none;
	// the Manager's signing mode decides whether that is fatal.
	Signature []byte
	// Name identifies the bundle in error messages -- a path for a file
	// source, a URL for a remote one.
	Name string
	// Version is an opaque token the source uses to detect a change. For
	// HTTP it is the ETag.
	Version string
}

// Source produces a policy bundle.
//
// Splitting this out of Manager.loadLocked is what makes a remotely served
// policy possible without a second load path: verification, parsing and
// validation stay exactly where they were, so a remote policy inherits the
// same trust guarantee as a local one rather than an approximation of it.
type Source interface {
	// Fetch returns the current bundle, or ErrNotModified.
	Fetch(ctx context.Context) (*Bundle, error)
	// Describe names the source for logs and errors.
	Describe() string
}

// FileSource reads a policy from a directory, with the optional SHA256SUMS
// manifest check.
//
// The manifest check lives here rather than in the Manager because it is a
// property of the local policy directory: it maps a basename to a digest, and
// a bundle that never came from that directory can never be listed in it.
type FileSource struct {
	Dir          string
	Name         string
	ManifestPath string
}

// Describe implements Source.
func (f *FileSource) Describe() string {
	return "file:" + f.Dir + "/" + f.Name
}

// Fetch implements Source.
//
// A missing signature is not an error here. The Manager's signing mode is what
// decides whether an unsigned policy may load, and reporting the absence as a
// read failure would turn `signing: off` into a hard error for every policy
// nobody signed.
func (f *FileSource) Fetch(context.Context) (*Bundle, error) {
	path, err := ResolvePolicyPath(f.Dir, f.Name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	if f.ManifestPath != "" {
		if err := verifyHash(path, data, f.ManifestPath); err != nil {
			return nil, err
		}
	}
	sig, err := os.ReadFile(path + ".sig")
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	return &Bundle{Data: data, Signature: sig, Name: path}, nil
}

// DefaultRemoteMaxBytes caps a fetched policy document.
//
// The server is untrusted -- the signing key is the trust root, not the
// transport -- so an unbounded read is a denial-of-service surface against
// the daemon. 4 MiB is far above any policy this schema produces; the largest
// in-tree example is a few kilobytes.
const DefaultRemoteMaxBytes int64 = 4 << 20

// defaultRemoteTimeout bounds one fetch. A poll that hangs holds no
// enforcement open -- the previous policy stays in force -- but it does stop
// the next update arriving, so it must not hang forever.
const defaultRemoteTimeout = 30 * time.Second

// RemoteSource fetches a signed policy over HTTP with a conditional GET.
//
// Modelled on internal/threatfeed/syncer.go, which is the in-tree precedent
// for this shape: If-None-Match honouring 304, a bounded read with an explicit
// truncation error rather than a silent prefix, and no clearing of what is
// already installed when a fetch fails.
//
// The signature travels in a header rather than the body so the body is the
// exact bytes that were signed. Reading it out of a JSON envelope would mean
// re-encoding before verification, and any difference in that round trip
// invalidates a signature that was actually fine.
type RemoteSource struct {
	// URL is the policy endpoint.
	URL string
	// Client is the HTTP client. Nil uses one with defaultRemoteTimeout.
	Client *http.Client
	// MaxBytes caps the document. Zero uses DefaultRemoteMaxBytes.
	MaxBytes int64
	// Header carries additional request headers, e.g. authentication.
	Header http.Header
	// Wait requests long-polling: the server holds the request open until
	// the policy changes or the duration elapses. Zero disables it, and a
	// server that ignores the parameter simply answers immediately.
	Wait time.Duration

	mu   sync.Mutex
	etag string
}

// SignatureHeader carries the detached signature JSON, base64-free: the .sig
// file is JSON already, so it goes in the header as-is.
const SignatureHeader = "X-Agentmon-Policy-Signature"

// NewRemoteSource validates the URL and returns a source.
func NewRemoteSource(rawURL string) (*RemoteSource, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return nil, fmt.Errorf("policy source url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("policy source url %q must be http or https", rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("policy source url %q has no host", rawURL)
	}
	return &RemoteSource{URL: u.String()}, nil
}

// Describe implements Source.
func (r *RemoteSource) Describe() string { return "remote:" + sanitizeSourceURL(r.URL) }

// Fetch implements Source.
func (r *RemoteSource) Fetch(ctx context.Context) (*Bundle, error) {
	r.mu.Lock()
	etag := r.etag
	r.mu.Unlock()

	target := r.URL
	if r.Wait > 0 {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + "wait=" + r.Wait.String()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("build policy request: %w", err)
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/yaml")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	client := r.Client
	if client == nil {
		timeout := defaultRemoteTimeout
		if r.Wait > 0 {
			// The server is expected to hold the request for Wait, so a
			// timeout at the default would abort every long poll.
			timeout = r.Wait + defaultRemoteTimeout
		}
		client = &http.Client{Timeout: timeout}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch policy from %s: %w", sanitizeSourceURL(r.URL), err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusNotModified {
		return nil, ErrNotModified
	}
	if resp.StatusCode != http.StatusOK {
		// The body may carry the server's error text and may also echo the
		// request. Only the status is surfaced: this reaches the log.
		return nil, fmt.Errorf("policy server %s returned HTTP %d", sanitizeSourceURL(r.URL), resp.StatusCode)
	}

	max := r.MaxBytes
	if max <= 0 {
		max = DefaultRemoteMaxBytes
	}
	// One byte past the cap is how truncation is detected at all: a read of
	// exactly max cannot tell a document that fits from one that was cut, and
	// parsing a cut document would either fail confusingly or -- worse --
	// succeed with the rules after the cut missing.
	lr := &io.LimitedReader{R: resp.Body, N: max + 1}
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read policy from %s: %w", sanitizeSourceURL(r.URL), err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("policy from %s exceeds the %d byte limit", sanitizeSourceURL(r.URL), max)
	}

	b := &Bundle{
		Data:      data,
		Signature: []byte(resp.Header.Get(SignatureHeader)),
		Name:      sanitizeSourceURL(r.URL),
		Version:   resp.Header.Get("ETag"),
	}
	if len(b.Signature) == 0 {
		b.Signature = nil
	}

	// Record the ETag only after the body was read whole. Recording it on a
	// truncated or failed read would make the next conditional GET return 304
	// for a document this agent never actually installed.
	if b.Version != "" {
		r.mu.Lock()
		r.etag = b.Version
		r.mu.Unlock()
	}
	return b, nil
}

// sanitizeSourceURL strips query and userinfo before a URL reaches a log. A
// policy endpoint can carry a token in either.
func sanitizeSourceURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable url>"
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}
