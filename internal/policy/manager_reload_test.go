package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const reloadPolicyA = `version: 1
name: a
`

const reloadPolicyB = `version: 1
name: b
`

func managerOn(src Source) *Manager {
	m := NewManager("", "unused", nil, "", "")
	m.SetSource(src)
	return m
}

func TestReloadContext_KeepsTheLoadedPolicyOnAFetchFailure(t *testing.T) {
	src := &stubSource{
		bundles: []*Bundle{{Data: []byte(reloadPolicyA)}},
		errs:    []error{nil, errors.New("connection refused")},
	}
	m := managerOn(src)

	if _, err := m.ReloadContext(context.Background()); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	doc, err := m.ReloadContext(context.Background())
	if err == nil {
		t.Fatal("a failed fetch was reported as success")
	}
	if doc == nil || doc.Name != "a" {
		t.Fatalf("reload returned %v; the caller must get the policy still in force", doc)
	}
	// The important half: Get() must not start failing because one poll
	// could not reach the server. Every session creation calls it.
	got, gerr := m.Get()
	if gerr != nil {
		t.Fatalf("Get() after a failed poll: %v", gerr)
	}
	if got.Name != "a" {
		t.Errorf("Get() = %q, want the last good policy", got.Name)
	}
}

func TestReloadContext_KeepsTheLoadedPolicyOnAParseFailure(t *testing.T) {
	src := &stubSource{bundles: []*Bundle{
		{Data: []byte(reloadPolicyA)},
		{Data: []byte("not: [a policy")},
	}}
	m := managerOn(src)

	if _, err := m.ReloadContext(context.Background()); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	if _, err := m.ReloadContext(context.Background()); err == nil {
		t.Fatal("a malformed document was installed")
	}
	got, gerr := m.Get()
	if gerr != nil || got.Name != "a" {
		t.Fatalf("Get() = (%v, %v), want the previous policy", got, gerr)
	}
}

func TestReloadContext_FirstLoadFailureIsFailClosed(t *testing.T) {
	m := managerOn(&stubSource{errs: []error{errors.New("connection refused")}})

	if _, err := m.ReloadContext(context.Background()); err == nil {
		t.Fatal("the first load succeeded with no policy")
	}
	// Nothing was ever loaded, so there is nothing to keep. Get() must fail
	// rather than hand out a nil policy.
	if _, err := m.Get(); err == nil {
		t.Fatal("Get() returned no error with no policy ever loaded")
	}
}

func TestReloadContext_InstallsANewDocument(t *testing.T) {
	src := &stubSource{bundles: []*Bundle{
		{Data: []byte(reloadPolicyA)},
		{Data: []byte(reloadPolicyB)},
	}}
	m := managerOn(src)

	first, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("first reload: %v", err)
	}
	second, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("second reload: %v", err)
	}
	if second.Name != "b" {
		t.Errorf("installed %q, want b", second.Name)
	}
	if first == second {
		t.Error("a changed document returned the same pointer; the poller detects change by pointer")
	}
}

func TestReloadContext_NotModifiedKeepsTheSamePointer(t *testing.T) {
	src := &stubSource{
		bundles: []*Bundle{{Data: []byte(reloadPolicyA)}},
		errs:    []error{nil, ErrNotModified},
	}
	m := managerOn(src)

	first, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("first reload: %v", err)
	}
	second, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("304 was reported as a failure: %v", err)
	}
	if first != second {
		t.Error("a 304 produced a new policy pointer, so the poller would report a change on every quiet poll")
	}
}

func TestSourceDescription_NamesTheConfiguredSource(t *testing.T) {
	m := NewManager("/etc/agentmon/policies", "default", nil, "", "")
	if got := m.SourceDescription(); !strings.Contains(got, "/etc/agentmon/policies") {
		t.Errorf("SourceDescription() = %q", got)
	}
	m.SetSource(&stubSource{})
	if got := m.SourceDescription(); got != "stub" {
		t.Errorf("SourceDescription() = %q after SetSource", got)
	}
}

func TestReloadContext_IdenticalBytesKeepTheSamePolicy(t *testing.T) {
	src := &stubSource{bundles: []*Bundle{
		{Data: []byte(reloadPolicyA)},
		{Data: []byte(reloadPolicyA)},
	}}
	m := managerOn(src)

	first, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("first reload: %v", err)
	}
	second, err := m.ReloadContext(context.Background())
	if err != nil {
		t.Fatalf("second reload: %v", err)
	}
	// A source with no change token -- or a server that sends no ETag --
	// returns the same bytes every poll. A new pointer there would look like a
	// change and rebuild every session's engine every interval.
	if first != second {
		t.Error("identical bytes produced a new policy pointer")
	}
}

func TestReloadContext_IdenticalBytesStillVerify(t *testing.T) {
	m := managerOn(&stubSource{bundles: []*Bundle{
		{Data: []byte(reloadPolicyA)},
		{Data: []byte(reloadPolicyA)},
	}})
	if _, err := m.ReloadContext(context.Background()); err != nil {
		t.Fatalf("first reload: %v", err)
	}
	// Turn signing on between the loads. Skipping verification for bytes that
	// already loaded would keep a bundle installable after its key was
	// revoked, so the second load must still fail.
	m.SetSigningConfig("enforce", t.TempDir())
	if _, err := m.ReloadContext(context.Background()); err == nil {
		t.Fatal("identical bytes bypassed signature verification")
	}
}

func TestCached_IsNilBeforeTheFirstLoadAndDoesNotFetch(t *testing.T) {
	src := &stubSource{bundles: []*Bundle{{Data: []byte(reloadPolicyA)}}}
	m := managerOn(src)

	if m.Cached() != nil {
		t.Error("Cached() returned a policy before anything loaded")
	}
	if src.calls != 0 {
		t.Fatalf("Cached() fetched %d times; it must not fetch", src.calls)
	}
	if _, err := m.Get(); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m.Cached() == nil {
		t.Error("Cached() is nil after a successful load")
	}
	if src.calls != 1 {
		t.Errorf("fetches = %d, want 1", src.calls)
	}
}
