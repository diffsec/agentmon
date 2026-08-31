package onnxrt_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/diffsec/agentmon/internal/inspect/provider/onnxrt"
)

// openLibrary loads ONNX Runtime or skips.
//
// Skipping rather than failing is deliberate: the library is an operator
// install, not a build dependency, so CI and most developer machines will not
// have it. The tests that need it say so in their skip message, and
// TestFindLibrary_ReportsNotFoundClearly still runs everywhere.
func openLibrary(t *testing.T) *onnxrt.Library {
	t.Helper()
	if _, err := onnxrt.FindLibrary(); err != nil {
		t.Skipf("no ONNX Runtime on this machine: %v", err)
	}
	lib, err := onnxrt.Open("")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(lib.Close)
	return lib
}

func loadModel(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read model: %v", err)
	}
	return data
}

// TestRun_Inference is the end-to-end proof that Go can drive ONNX Runtime
// with no cgo.
//
// mul_1.onnx multiplies its input by a baked-in initializer of [1..6], so
// feeding [1..6] must produce the squares. An arithmetic result rather than
// "no error" is the point: a binding that indexed the wrong OrtApi member, or
// mis-strided the tensor, would still return successfully.
func TestRun_Inference(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSession(loadModel(t, "mul_1.onnx"), onnxrt.SessionOptions{IntraOpThreads: 1})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	in := onnxrt.NewFloatTensor([]int64{3, 2}, []float32{1, 2, 3, 4, 5, 6})
	out, err := sess.Run(map[string]*onnxrt.Tensor{"X": in}, []string{"Y"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d outputs, want 1", len(out))
	}

	want := []float32{1, 4, 9, 16, 25, 36}
	if len(out[0].Floats) != len(want) {
		t.Fatalf("got %d values, want %d", len(out[0].Floats), len(want))
	}
	for i := range want {
		if out[0].Floats[i] != want[i] {
			t.Errorf("output[%d] = %v, want %v (full: %v)", i, out[0].Floats[i], want[i], out[0].Floats)
		}
	}
	if len(out[0].Shape) != 2 || out[0].Shape[0] != 3 || out[0].Shape[1] != 2 {
		t.Errorf("shape = %v, want [3 2]", out[0].Shape)
	}
}

// TestRun_OutputIsCopiedNotAliased. readValue copies out of the OrtValue
// because the value is released when Run returns; a slice aliasing it would
// be a use-after-free that reads plausible numbers rather than crashing.
func TestRun_OutputIsCopiedNotAliased(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSession(loadModel(t, "mul_1.onnx"), onnxrt.SessionOptions{IntraOpThreads: 1})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	run := func(v float32) []float32 {
		in := onnxrt.NewFloatTensor([]int64{3, 2}, []float32{v, v, v, v, v, v})
		out, err := sess.Run(map[string]*onnxrt.Tensor{"X": in}, []string{"Y"})
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		return out[0].Floats
	}

	first := run(1)
	firstCopy := append([]float32(nil), first...)
	_ = run(10) // a second run reuses ONNX Runtime's buffers

	for i := range first {
		if first[i] != firstCopy[i] {
			t.Fatalf("the first result changed after a second run: %v then %v; the output aliases runtime memory", firstCopy, first)
		}
	}
}

// TestSession_InputAndOutputNames exercises the allocator path, which frees
// each name after copying it. A leak there is once per name per call, which
// only shows up after a daemon has been running a while.
func TestSession_InputAndOutputNames(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSession(loadModel(t, "mul_1.onnx"), onnxrt.SessionOptions{})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	in, err := sess.InputNames()
	if err != nil {
		t.Fatalf("InputNames: %v", err)
	}
	if len(in) != 1 || in[0] != "X" {
		t.Errorf("InputNames = %v, want [X]", in)
	}

	out, err := sess.OutputNames()
	if err != nil {
		t.Fatalf("OutputNames: %v", err)
	}
	if len(out) != 1 || out[0] != "Y" {
		t.Errorf("OutputNames = %v, want [Y]", out)
	}
}

// TestRun_RejectsMismatchedShape: a shape that disagrees with the data length
// would have ONNX Runtime read past the end of a Go slice.
func TestRun_RejectsMismatchedShape(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSession(loadModel(t, "mul_1.onnx"), onnxrt.SessionOptions{})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	bad := onnxrt.NewFloatTensor([]int64{3, 2}, []float32{1, 2, 3}) // says 6, has 3
	if _, err := sess.Run(map[string]*onnxrt.Tensor{"X": bad}, []string{"Y"}); err == nil {
		t.Fatal("a tensor whose shape overruns its data was accepted")
	} else if !strings.Contains(err.Error(), "needs 6 values") {
		t.Errorf("err = %v, want it to name the mismatch", err)
	}
}

// TestRun_UnknownNamesAreAnError. ONNX Runtime reports these; the binding
// must surface the message rather than swallow the status.
func TestRun_UnknownNamesAreAnError(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSession(loadModel(t, "mul_1.onnx"), onnxrt.SessionOptions{})
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()

	in := onnxrt.NewFloatTensor([]int64{3, 2}, []float32{1, 2, 3, 4, 5, 6})
	_, err = sess.Run(map[string]*onnxrt.Tensor{"NotAnInput": in}, []string{"Y"})
	if err == nil {
		t.Fatal("an unknown input name was accepted")
	}
	if !strings.Contains(err.Error(), "onnxrt:") {
		t.Errorf("err should be wrapped by this package, got %v", err)
	}
}

// TestNewSession_RejectsGarbage: a file that is not a model must fail at load
// rather than at the first inference.
func TestNewSession_RejectsGarbage(t *testing.T) {
	lib := openLibrary(t)
	if _, err := lib.NewSession([]byte("this is not an onnx model"), onnxrt.SessionOptions{}); err == nil {
		t.Fatal("garbage was accepted as a model")
	}
	if _, err := lib.NewSession(nil, onnxrt.SessionOptions{}); err == nil {
		t.Fatal("an empty model was accepted")
	}
}

// TestFindLibrary_ReportsNotFoundClearly runs everywhere, including where no
// runtime is installed. "Not installed" has to be distinguishable from
// "failed to load": the first is an operator action, the second is a bug.
func TestFindLibrary_ReportsNotFoundClearly(t *testing.T) {
	t.Setenv(onnxrt.LibraryEnv, filepath.Join(t.TempDir(), "nope.dylib"))

	_, err := onnxrt.FindLibrary()
	if err == nil {
		t.Fatal("a nonexistent path was accepted")
	}
	if !strings.Contains(err.Error(), onnxrt.LibraryEnv) {
		t.Errorf("err should name the env var so the operator knows what to fix, got %v", err)
	}

	if _, err := onnxrt.Open(""); err == nil {
		t.Fatal("Open succeeded with a bad library path")
	}
}

// TestFindLibrary_NotFoundIsSentinel lets callers branch on absence.
func TestFindLibrary_NotFoundIsSentinel(t *testing.T) {
	// An empty env var falls through to the default paths. On a machine with
	// a runtime installed there this legitimately succeeds, so only the
	// error case is asserted.
	t.Setenv(onnxrt.LibraryEnv, "")
	if _, err := onnxrt.FindLibrary(); err != nil && !errors.Is(err, onnxrt.ErrLibraryNotFound) {
		t.Errorf("err = %v, want it to wrap ErrLibraryNotFound", err)
	}
}

// TestNewSessionFromPath_Inference covers the loader Privacy Filter needs.
//
// NewSession cannot load that model at all: its graph is 160KB and its weights
// are a separate 917MB .onnx_data file, which ONNX Runtime resolves relative
// to the model's directory and therefore only finds when given a path. The
// arithmetic is asserted for the same reason as in TestRun_Inference -- a
// wrong OrtApi index still returns successfully.
func TestNewSessionFromPath_Inference(t *testing.T) {
	lib := openLibrary(t)
	sess, err := lib.NewSessionFromPath(filepath.Join("testdata", "mul_1.onnx"), onnxrt.SessionOptions{IntraOpThreads: 1})
	if err != nil {
		t.Fatalf("NewSessionFromPath: %v", err)
	}
	defer sess.Close()

	in := onnxrt.NewFloatTensor([]int64{3, 2}, []float32{1, 2, 3, 4, 5, 6})
	out, err := sess.Run(map[string]*onnxrt.Tensor{"X": in}, []string{"Y"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	want := []float32{1, 4, 9, 16, 25, 36}
	for i := range want {
		if out[0].Floats[i] != want[i] {
			t.Errorf("output[%d] = %v, want %v", i, out[0].Floats[i], want[i])
		}
	}
}

// TestNewSessionFromPath_MissingFile must fail before reaching ONNX Runtime,
// so the error names the path rather than surfacing a C-level message.
func TestNewSessionFromPath_MissingFile(t *testing.T) {
	lib := openLibrary(t)
	_, err := lib.NewSessionFromPath(filepath.Join(t.TempDir(), "absent.onnx"), onnxrt.SessionOptions{})
	if err == nil {
		t.Fatal("a nonexistent model path was accepted")
	}
	if !strings.Contains(err.Error(), "absent.onnx") {
		t.Errorf("err should name the path, got %v", err)
	}
	if _, err := lib.NewSessionFromPath("", onnxrt.SessionOptions{}); err == nil {
		t.Fatal("an empty model path was accepted")
	}
}
