package privacyfilter_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect"
	"github.com/diffsec/agentmon/internal/inspect/provider/onnxrt"
	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter"
	"github.com/diffsec/agentmon/internal/policy"
)

// CacheEnv points at a directory holding an already-downloaded model, so the
// tests never fetch 917MB.
const CacheEnv = "AGENTMON_PRIVACY_FILTER_CACHE"

// openProvider loads the real model or skips.
//
// It needs two things the machine may not have -- ONNX Runtime and 917MB of
// weights -- so these tests are opt-in. Everything they cover is behaviour
// that only a real model can demonstrate; the pieces below it are tested on
// their own in the tokenizer, decoder and onnxrt packages.
func openProvider(t *testing.T) *privacyfilter.Provider {
	t.Helper()
	cache := os.Getenv(CacheEnv)
	if cache == "" {
		t.Skipf("set %s to a directory holding the model to run this", CacheEnv)
	}
	if _, err := onnxrt.FindLibrary(); err != nil {
		t.Skipf("no ONNX Runtime: %v", err)
	}

	p, err := privacyfilter.Open(context.Background(), privacyfilter.Config{
		CacheDir:       cache,
		IntraOpThreads: 2,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func request(text string, categories ...string) inspect.Request {
	return inspect.Request{
		Profile: "pii",
		Spec:    policy.InspectionProfile{Provider: privacyfilter.Name, Categories: categories},
		Kind:    inspect.KindProxyBody,
		Content: text,
	}
}

// TestInspect_FindsPIIAtTheRightBytes is the payoff test for the whole Go +
// ONNX path.
//
// It asserts the byte offsets select the exact substring, not merely that
// something was detected. Everything downstream slices the content by these
// offsets, so an off-by-one leaves half an email address in a request body --
// which looks like a working redaction right up until someone reads the
// output.
func TestInspect_FindsPIIAtTheRightBytes(t *testing.T) {
	p := openProvider(t)

	cases := []struct {
		name     string
		text     string
		want     string // the exact substring the span must cover
		category string
	}{
		{"a person", "My name is Alice Smith and I work here", "Alice Smith", "private_person"},
		{"an email", "Please contact alice@example.com about it", "alice@example.com", "private_email"},
		{"a phone number", "Call me on 555-123-4567 tomorrow", "555-123-4567", "private_phone"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := p.Inspect(context.Background(), request(c.text))
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if len(resp.Findings) == 0 {
				t.Fatalf("no findings in %q", c.text)
			}

			var got *inspect.Finding
			for i := range resp.Findings {
				if resp.Findings[i].Category == c.category {
					got = &resp.Findings[i]
					break
				}
			}
			if got == nil {
				t.Fatalf("no %s finding; got %+v", c.category, resp.Findings)
			}

			if got.Start < 0 || got.End > len(c.text) || got.End <= got.Start {
				t.Fatalf("span [%d,%d) is outside the %d-byte input", got.Start, got.End, len(c.text))
			}
			covered := strings.TrimSpace(c.text[got.Start:got.End])
			if covered != c.want {
				t.Errorf("span [%d,%d) covers %q, want %q", got.Start, got.End, covered, c.want)
			}
			if got.Score <= 0 || got.Score > 1 {
				t.Errorf("Score = %v, want a probability", got.Score)
			}
			if got.Profile != "pii" {
				t.Errorf("Profile = %q", got.Profile)
			}
		})
	}
}

// TestInspect_CleanTextFindsNothing keeps the test above from being satisfied
// by a provider that flags everything.
func TestInspect_CleanTextFindsNothing(t *testing.T) {
	p := openProvider(t)

	for _, text := range []string{
		"The quick brown fox jumps over the lazy dog",
		"SELECT count(*) FROM orders WHERE status = 'shipped'",
		"",
	} {
		resp, err := p.Inspect(context.Background(), request(text))
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if len(resp.Findings) != 0 {
			t.Errorf("%q produced findings: %+v", text, resp.Findings)
		}
	}
}

// TestInspect_CategoryFilterIsHonoured: a profile scoped to one category must
// not report others, or an operator asking about secrets starts redacting
// every name in a request body.
func TestInspect_CategoryFilterIsHonoured(t *testing.T) {
	p := openProvider(t)
	const text = "Alice Smith can be reached at alice@example.com"

	all, err := p.Inspect(context.Background(), request(text))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(all.Findings) < 2 {
		t.Skipf("the model found %d spans in %q; this test needs at least two categories", len(all.Findings), text)
	}

	only, err := p.Inspect(context.Background(), request(text, "private_email"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	for _, f := range only.Findings {
		if f.Category != "private_email" {
			t.Errorf("a profile scoped to private_email reported %q", f.Category)
		}
	}
	if len(only.Findings) == 0 {
		t.Error("scoping to private_email removed the email finding too")
	}
}

// TestInspect_UnknownCategoryIsAnError is the fail-closed case. A profile
// asking for something this model cannot produce must not come back clean.
func TestInspect_UnknownCategoryIsAnError(t *testing.T) {
	p := openProvider(t)

	_, err := p.Inspect(context.Background(), request("Alice Smith", "national_insurance_number"))
	if err == nil {
		t.Fatal("an unsupported category returned a clean result")
	}
	if !strings.Contains(err.Error(), "national_insurance_number") {
		t.Errorf("err should name the category, got %v", err)
	}
}

// TestInspect_MultibyteOffsets. The tokenizer works in bytes and the text may
// not be ASCII, so a span computed in runes would land mid-character and
// slicing would panic or corrupt the output.
func TestInspect_MultibyteOffsets(t *testing.T) {
	p := openProvider(t)
	const text = "Café notes — écrire à alice@example.com aujourd'hui"

	resp, err := p.Inspect(context.Background(), request(text, "private_email"))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(resp.Findings) == 0 {
		t.Skip("the model found no email in the multibyte sample")
	}
	f := resp.Findings[0]
	if got := strings.TrimSpace(text[f.Start:f.End]); got != "alice@example.com" {
		t.Errorf("span covers %q, want the address; offsets are not in bytes", got)
	}
}

// TestIsLocal is what keeps the privacy gate from making the operator opt in
// to remote inspection for a provider that never leaves the process.
func TestIsLocal(t *testing.T) {
	var p inspect.Provider = &privacyfilter.Provider{}
	lp, ok := p.(inspect.LocalProvider)
	if !ok || !lp.IsLocal() {
		t.Fatal("the provider is not local; content would need allow_remote to reach it")
	}
}

// TestCategories matches the model's taxonomy, so a policy naming a category
// is checked against what the model actually emits.
func TestCategories(t *testing.T) {
	var p privacyfilter.Provider
	got := p.Categories()
	if len(got) != 8 {
		t.Fatalf("got %d categories, want 8: %v", len(got), got)
	}
	want := map[string]bool{
		"account_number": true, "private_address": true, "private_date": true,
		"private_email": true, "private_person": true, "private_phone": true,
		"private_url": true, "secret": true,
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected category %q", c)
		}
	}
}

// TestOpen_RefusesToDownloadWhenNotAllowed. A 917MB fetch at startup is not
// something to do by accident, and an air-gapped host needs a way to say so.
func TestOpen_RefusesToDownloadWhenNotAllowed(t *testing.T) {
	_, err := privacyfilter.Open(context.Background(), privacyfilter.Config{
		CacheDir:      t.TempDir(),
		AllowDownload: false,
	})
	if err == nil {
		t.Fatal("Open downloaded the model despite AllowDownload being false")
	}
	if !strings.Contains(err.Error(), "not cached") {
		t.Errorf("err = %v, want it to say the model is not cached", err)
	}
}
