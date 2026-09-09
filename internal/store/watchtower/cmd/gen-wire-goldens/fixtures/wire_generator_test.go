package fixtures_test

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	wtpv1 "github.com/canyonroad/wtp-protos/gen/go/canyonroad/wtp/v1"
	"github.com/diffsec/agentmon/internal/store/watchtower/cmd/gen-wire-goldens/fixtures"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/proto"
)

func TestWireGoldens_GeneratorReproducible(t *testing.T) {
	for _, f := range fixtures.All() {
		t.Run(f.Name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", f.Name))
			if err != nil {
				t.Fatalf("read golden %s: %v", f.Name, err)
			}
			got, err := proto.Marshal(f.Message)
			if err != nil {
				t.Fatalf("marshal fixture %s: %v", f.Name, err)
			}
			if compressedPayload(f.Message) != nil {
				compareCompressed(t, f.Name, got, want)
				return
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("generator output drifted from golden %s\n  generator produced %d bytes\n  golden has        %d bytes\n  re-run: go run ./internal/store/watchtower/cmd/gen-wire-goldens",
					f.Name, len(got), len(want))
			}
		})
	}
}

// compressedPayload returns the compressed body of an EventBatch, or nil for
// every other fixture.
func compressedPayload(m proto.Message) []byte {
	b, ok := m.(*wtpv1.EventBatch)
	if !ok {
		return nil
	}
	return b.GetCompressedPayload()
}

// compareCompressed checks a compressed fixture by what it decodes to, not by
// its compressed bytes.
//
// The compressed bytes are not part of the wire contract. gzip here is stdlib
// compress/gzip, whose DEFLATE strategy is a property of the Go toolchain: the
// checked-in golden holds a deflated block, and the toolchain in use now emits
// a stored block for the same input at the same level. Both are valid gzip,
// both carry CRC 6ad82ca4 over 90 bytes, and both decode to the same payload.
// Byte equality made this test fail on a Go upgrade and say "generator output
// drifted", which is the one thing that had not happened.
//
// What is still asserted is everything the receiver depends on: the envelope
// fields, the declared algorithm, and the exact bytes the payload decodes to.
// A wrong compression level still decodes, and internal/store/watchtower/
// transport/compress covers levels directly (TestGzipEncoder_LevelBounds,
// TestZstdEncoder_LevelBounds).
func compareCompressed(t *testing.T, name string, got, want []byte) {
	t.Helper()
	var gotBatch, wantBatch wtpv1.EventBatch
	if err := proto.Unmarshal(got, &gotBatch); err != nil {
		t.Fatalf("unmarshal generated %s: %v", name, err)
	}
	if err := proto.Unmarshal(want, &wantBatch); err != nil {
		t.Fatalf("unmarshal golden %s: %v", name, err)
	}

	if gotBatch.GetCompression() != wantBatch.GetCompression() {
		t.Errorf("%s: compression = %v, golden has %v", name, gotBatch.GetCompression(), wantBatch.GetCompression())
	}
	if gotBatch.GetFromSequence() != wantBatch.GetFromSequence() ||
		gotBatch.GetToSequence() != wantBatch.GetToSequence() ||
		gotBatch.GetGeneration() != wantBatch.GetGeneration() {
		t.Errorf("%s: envelope drifted: got from=%d to=%d gen=%d, golden from=%d to=%d gen=%d",
			name, gotBatch.GetFromSequence(), gotBatch.GetToSequence(), gotBatch.GetGeneration(),
			wantBatch.GetFromSequence(), wantBatch.GetToSequence(), wantBatch.GetGeneration())
	}

	gotPayload := decompress(t, name, gotBatch.GetCompression(), gotBatch.GetCompressedPayload())
	wantPayload := decompress(t, name, wantBatch.GetCompression(), wantBatch.GetCompressedPayload())
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Fatalf("%s: decoded payload drifted from golden\n  generator produced %d bytes\n  golden has        %d bytes\n  re-run: go run ./internal/store/watchtower/cmd/gen-wire-goldens",
			name, len(gotPayload), len(wantPayload))
	}
}

// decompress inflates a fixture payload according to its declared algorithm.
// An algorithm the test does not handle fails rather than passing silently,
// so adding a third one cannot quietly skip the payload comparison.
func decompress(t *testing.T, name string, algo wtpv1.Compression, payload []byte) []byte {
	t.Helper()
	switch algo {
	case wtpv1.Compression_COMPRESSION_GZIP:
		r, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("%s: gzip reader: %v", name, err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: gzip payload: %v", name, err)
		}
		return out
	case wtpv1.Compression_COMPRESSION_ZSTD:
		r, err := zstd.NewReader(bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("%s: zstd reader: %v", name, err)
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			t.Fatalf("%s: zstd payload: %v", name, err)
		}
		return out
	default:
		t.Fatalf("%s: fixture declares compression %v, which this test cannot decode", name, algo)
		return nil
	}
}

// TestWireGoldens_NoOrphanGoldens guards against fixture set drift in the
// other direction: a stale .bin file lingering in testdata/ after the
// fixture that produced it was renamed or removed. Together with
// TestWireGoldens_GeneratorReproducible (byte-equality for known fixtures)
// it makes the fixture set authoritatively defined by fixtures.All().
func TestWireGoldens_NoOrphanGoldens(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata dir: %v", err)
	}

	wantNames := map[string]bool{}
	for _, f := range fixtures.All() {
		wantNames[f.Name] = true
	}

	gotNames := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".bin") {
			continue
		}
		gotNames[e.Name()] = true
		if !wantNames[e.Name()] {
			t.Errorf("orphan golden %q in testdata/ has no fixture in fixtures.All() — remove it or add a fixture", e.Name())
		}
	}

	for name := range wantNames {
		if !gotNames[name] {
			t.Errorf("fixture %q has no checked-in golden — run: go run ./internal/store/watchtower/cmd/gen-wire-goldens", name)
		}
	}
}
