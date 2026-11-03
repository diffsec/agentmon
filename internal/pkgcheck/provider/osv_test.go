package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/diffsec/agentmon/internal/pkgcheck"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testdataPath(name string) string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata", name)
}

func TestOSVProvider_Name(t *testing.T) {
	p := NewOSVProvider(OSVConfig{})
	assert.Equal(t, "osv", p.Name())
}

func TestOSVProvider_Capabilities(t *testing.T) {
	p := NewOSVProvider(OSVConfig{})
	assert.Equal(t, []pkgcheck.FindingType{pkgcheck.FindingVulnerability}, p.Capabilities())
}

func TestOSVProvider_Interface(t *testing.T) {
	var _ pkgcheck.CheckProvider = NewOSVProvider(OSVConfig{})
}

func TestOSVProvider_BatchQuery(t *testing.T) {
	fixture, err := os.ReadFile(testdataPath("osv_batch_response.json"))
	require.NoError(t, err)

	var receivedBody osvBatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/querybatch", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &receivedBody))

		w.Header().Set("Content-Type", "application/json")
		w.Write(fixture)
	}))
	defer server.Close()

	p := NewOSVProvider(OSVConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.17.1"},
			{Name: "lodash", Version: "4.17.21"},
		},
	})
	require.NoError(t, err)

	// Verify the request was correctly formed.
	require.Len(t, receivedBody.Queries, 2)
	assert.Equal(t, "express", receivedBody.Queries[0].Package.Name)
	assert.Equal(t, "npm", receivedBody.Queries[0].Package.Ecosystem)
	assert.Equal(t, "4.17.1", receivedBody.Queries[0].Version)

	// Verify findings.
	assert.Equal(t, "osv", resp.Provider)
	require.Len(t, resp.Findings, 1) // Only express has vulns.

	f := resp.Findings[0]
	assert.Equal(t, pkgcheck.FindingVulnerability, f.Type)
	assert.Equal(t, "express", f.Package.Name)
	assert.Equal(t, "Test vulnerability in express", f.Title)
	assert.Equal(t, "GHSA-test-1234", f.Metadata["vuln_id"])
	require.Len(t, f.Links, 2)
	assert.Contains(t, f.Links[0], "GHSA-test-1234")

	// The CVSS:3.1 vector AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H => 9.8 => critical
	assert.Equal(t, pkgcheck.SeverityCritical, f.Severity)
}

func TestOSVProvider_PyPIEcosystem(t *testing.T) {
	var receivedBody osvBatchRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results": [{"vulns": []}]}`))
	}))
	defer server.Close()

	p := NewOSVProvider(OSVConfig{BaseURL: server.URL})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemPyPI,
		Packages: []pkgcheck.PackageRef{
			{Name: "requests", Version: "2.28.0"},
		},
	})
	require.NoError(t, err)

	require.Len(t, receivedBody.Queries, 1)
	assert.Equal(t, "PyPI", receivedBody.Queries[0].Package.Ecosystem)
}

func TestOSVProvider_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	p := NewOSVProvider(OSVConfig{BaseURL: server.URL})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.17.1"},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 500")
}

func TestOSVProvider_NoVulns(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"results": [{"vulns": []}]}`))
	}))
	defer server.Close()

	p := NewOSVProvider(OSVConfig{BaseURL: server.URL})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "express", Version: "4.18.0"},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Findings)
}

func TestMapOSVSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severities []osvSeverity
		expected   pkgcheck.Severity
	}{
		{
			name:       "no severity info",
			severities: nil,
			expected:   pkgcheck.SeverityMedium,
		},
		{
			name: "critical CVSS vector",
			severities: []osvSeverity{
				{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			},
			expected: pkgcheck.SeverityCritical,
		},
		{
			name: "high numeric score",
			severities: []osvSeverity{
				{Type: "CVSS_V3", Score: "7.5"},
			},
			expected: pkgcheck.SeverityHigh,
		},
		{
			name: "medium numeric score",
			severities: []osvSeverity{
				{Type: "CVSS_V3", Score: "5.0"},
			},
			expected: pkgcheck.SeverityMedium,
		},
		{
			name: "low numeric score",
			severities: []osvSeverity{
				{Type: "CVSS_V3", Score: "2.0"},
			},
			expected: pkgcheck.SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapOSVSeverity(tt.severities))
		})
	}
}

func TestParseCVSSBaseScore(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{
			name:     "numeric score",
			input:    "9.8",
			expected: 9.8,
		},
		{
			name:     "zero score",
			input:    "0.0",
			expected: 0.0,
		},
		{
			name:     "invalid string",
			input:    "not-a-score",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := parseCVSSBaseScore(tt.input)
			assert.InDelta(t, tt.expected, score, 0.01)
		})
	}
}

// TestOSVProvider_FetchesSeverity: /v1/querybatch returns only the ID of each
// vulnerability. The provider must fetch the record to learn the severity.
// Before, every OSV finding was medium, so no critical rule ever matched.
func TestOSVProvider_FetchesSeverity(t *testing.T) {
	var detailCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/querybatch":
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-crit","modified":"2024-01-01T00:00:00Z"},{"id":"GHSA-gone","modified":"2024-01-01T00:00:00Z"}]}]}`))
		case "/v1/vulns/GHSA-crit":
			detailCalls.Add(1)
			_, _ = w.Write([]byte(`{"id":"GHSA-crit","summary":"SQL injection","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	p := NewOSVProvider(OSVConfig{BaseURL: server.URL})
	req := pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemPyPI,
		Packages:  []pkgcheck.PackageRef{{Name: "django", Version: "2.2"}},
	}
	resp, err := p.CheckBatch(context.Background(), req)
	require.NoError(t, err)
	require.Len(t, resp.Findings, 2)
	assert.Equal(t, pkgcheck.SeverityCritical, resp.Findings[0].Severity)
	assert.Equal(t, "SQL injection", resp.Findings[0].Title)
	// A record that could not be fetched keeps the medium default, and the
	// response is marked partial.
	assert.Equal(t, pkgcheck.SeverityMedium, resp.Findings[1].Severity)
	assert.True(t, resp.Metadata.Partial)

	// The second check of the same package reuses the cached record.
	_, err = p.CheckBatch(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, int32(1), detailCalls.Load())
}
