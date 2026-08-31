// Package onnxrt calls ONNX Runtime from Go without cgo.
//
// It binds the C API through ebitengine/purego, so agentmon keeps pure-Go
// builds and cross-compilation while running a real inference engine. The
// cost is a shared library the operator must install; there is no static
// option, and the package refuses to guess where it is.
//
// The binding is deliberately narrow: enough to load a model, run it once and
// read the result. Every function it calls is listed in the generator's
// `wanted` set, so the API surface in use is enumerable rather than whatever
// happened to be reachable.
package onnxrt

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ONNX tensor element types, from ONNXTensorElementDataType.
const (
	tensorFloat = 1
	tensorInt64 = 7
)

// Logging levels, from OrtLoggingLevel. Warning keeps ONNX Runtime quiet on
// stderr without hiding real problems.
const loggingLevelWarning = 2

// GraphOptimizationLevel values, from GraphOptimizationLevel.
const graphOptAll = 99

// LibraryEnv names the environment variable holding the path to
// libonnxruntime. It is checked before any default location.
const LibraryEnv = "AGENTMON_ONNXRUNTIME_LIB"

// defaultLibraryPaths are searched when LibraryEnv is unset.
//
// The list is short and explicit on purpose. Scanning the loader path for
// anything called libonnxruntime would let a library dropped anywhere on
// LD_LIBRARY_PATH be loaded into the daemon, which is a code-execution
// primitive dressed up as a convenience.
var defaultLibraryPaths = []string{
	"/usr/local/lib/libonnxruntime.dylib",
	"/opt/homebrew/lib/libonnxruntime.dylib",
	"/usr/local/lib/libonnxruntime.so",
	"/usr/lib/libonnxruntime.so",
}

// ErrLibraryNotFound is returned when no ONNX Runtime library could be
// located. Callers use it to distinguish "not installed" from "failed to
// load", because the first is an operator action and the second is a bug.
var ErrLibraryNotFound = errors.New("onnxrt: no ONNX Runtime library found")

// Library is a loaded ONNX Runtime.
type Library struct {
	// api and env are C pointers held as unsafe.Pointer rather than
	// uintptr. A uintptr is just a number to the compiler and to go vet:
	// keeping the real pointer type means the table is indexed with
	// unsafe.Add, which exists for exactly this, instead of hand-rolled
	// address arithmetic that vet cannot distinguish from a mistake.
	api unsafe.Pointer
	env unsafe.Pointer

	mu     sync.Mutex
	closed bool
}

// FindLibrary returns the path that Open would use, or ErrLibraryNotFound.
func FindLibrary() (string, error) {
	if p := os.Getenv(LibraryEnv); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("onnxrt: %s is set to %q: %w", LibraryEnv, p, err)
		}
		return p, nil
	}
	for _, p := range defaultLibraryPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%w; set %s to its path", ErrLibraryNotFound, LibraryEnv)
}

// Open loads ONNX Runtime. An empty path uses FindLibrary.
func Open(path string) (*Library, error) {
	if path == "" {
		p, err := FindLibrary()
		if err != nil {
			return nil, err
		}
		path = p
	}

	handle, err := purego.Dlopen(path, purego.RTLD_NOW|purego.RTLD_GLOBAL)
	if err != nil {
		return nil, fmt.Errorf("onnxrt: loading %q: %w", path, err)
	}
	sym, err := purego.Dlsym(handle, "OrtGetApiBase")
	if err != nil {
		return nil, fmt.Errorf("onnxrt: %q has no OrtGetApiBase; is it ONNX Runtime? %w", path, err)
	}

	base, _, _ := purego.SyscallN(sym)
	if base == 0 {
		return nil, fmt.Errorf("onnxrt: OrtGetApiBase returned NULL")
	}
	// OrtApiBase is { GetApi, GetVersionString }.
	getAPI := (*[2]uintptr)(fromC(base))[0]

	apiPtr, _, _ := purego.SyscallN(getAPI, apiVersion)
	if apiPtr == 0 {
		// A NULL here means the library predates the API version these
		// indices were generated from. Falling back to a version we have
		// not read the header for would index a struct of unknown shape.
		return nil, fmt.Errorf("onnxrt: %q does not implement ORT_API_VERSION %d; it is too old", path, apiVersion)
	}

	lib := &Library{api: fromC(apiPtr)}
	logID := cstring("agentmon")
	var env uintptr
	st, _, _ := purego.SyscallN(lib.fn(idxCreateEnv), loggingLevelWarning,
		uintptr(unsafe.Pointer(&logID[0])), uintptr(unsafe.Pointer(&env)))
	runtime.KeepAlive(logID)
	if err := lib.status(st, "CreateEnv"); err != nil {
		return nil, err
	}
	lib.env = fromC(env)
	return lib, nil
}

// Close releases the runtime environment. Sessions must be closed first.
func (l *Library) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.env == nil {
		return
	}
	purego.SyscallN(l.fn(idxReleaseEnv), toC(l.env))
	l.env = nil
	l.closed = true
}

// fn returns the i'th OrtApi function pointer.
func (l *Library) fn(i int) uintptr {
	return *(*uintptr)(unsafe.Add(l.api, uintptr(i)*unsafe.Sizeof(uintptr(0))))
}

// status turns an OrtStatus* into an error and releases it. A nil status is
// success.
func (l *Library) status(st uintptr, what string) error {
	if st == 0 {
		return nil
	}
	msg, _, _ := purego.SyscallN(l.fn(idxGetErrorMessage), st)
	err := fmt.Errorf("onnxrt: %s: %s", what, goString(msg))
	purego.SyscallN(l.fn(idxReleaseStatus), st)
	return err
}

// SessionOptions configures a session.
type SessionOptions struct {
	// IntraOpThreads bounds the threads one operator may use. Zero leaves
	// ONNX Runtime's default, which is one thread per core -- too many for a
	// daemon that must stay responsive while inspecting one request.
	IntraOpThreads int
}

// Session is a loaded model.
type Session struct {
	lib  *Library
	sess uintptr
	opts uintptr

	mu     sync.Mutex
	closed bool
}

// NewSession loads a model from memory.
//
// Use it only for a self-contained model. A graph whose weights live in
// separate .onnx_data files cannot be loaded this way: ONNX Runtime resolves
// those paths relative to the model's directory, which it does not know when
// handed bytes. Privacy Filter is such a model -- its graph is 160KB and its
// weights are 917MB alongside -- so that path uses NewSessionFromPath.
func (l *Library) NewSession(model []byte, opts SessionOptions) (*Session, error) {
	if len(model) == 0 {
		return nil, errors.New("onnxrt: empty model")
	}

	so, err := l.newSessionOptions(opts)
	if err != nil {
		return nil, err
	}
	var st uintptr

	var sess uintptr
	st, _, _ = purego.SyscallN(l.fn(idxCreateSessionFromArray), toC(l.env),
		uintptr(unsafe.Pointer(&model[0])), uintptr(len(model)), so, uintptr(unsafe.Pointer(&sess)))
	runtime.KeepAlive(model)
	if err := l.status(st, "CreateSessionFromArray"); err != nil {
		purego.SyscallN(l.fn(idxReleaseSessionOptions), so)
		return nil, err
	}

	return &Session{lib: l, sess: sess, opts: so}, nil
}

// NewSessionFromPath loads a model by path.
//
// This is the only way to load a model whose weights are in external
// .onnx_data files, because ONNX Runtime resolves those relative to the
// model's own directory and only learns that directory from the path. It also
// avoids reading a gigabyte of weights into Go's heap just to hand them
// straight back.
//
// The trade is that the file is read by ONNX Runtime, not by the caller, so a
// caller that verified a digest is trusting the file not to change in
// between. The model cache writes atomically and treats its directory as
// immutable once populated, which is what makes that safe.
func (l *Library) NewSessionFromPath(path string, opts SessionOptions) (*Session, error) {
	if path == "" {
		return nil, errors.New("onnxrt: empty model path")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("onnxrt: model %q: %w", path, err)
	}

	so, err := l.newSessionOptions(opts)
	if err != nil {
		return nil, err
	}

	// ORTCHAR_T is char on unix, so a plain NUL-terminated string is right.
	// It is wchar_t on Windows, which this project does not support.
	cpath := cstring(path)
	var sess uintptr
	st, _, _ := purego.SyscallN(l.fn(idxCreateSession), toC(l.env),
		uintptr(unsafe.Pointer(&cpath[0])), so, uintptr(unsafe.Pointer(&sess)))
	runtime.KeepAlive(cpath)
	if err := l.status(st, "CreateSession"); err != nil {
		purego.SyscallN(l.fn(idxReleaseSessionOptions), so)
		return nil, err
	}

	return &Session{lib: l, sess: sess, opts: so}, nil
}

// newSessionOptions builds and configures an OrtSessionOptions. The caller
// owns it and must release it, which Session.Close does.
func (l *Library) newSessionOptions(opts SessionOptions) (uintptr, error) {
	var so uintptr
	st, _, _ := purego.SyscallN(l.fn(idxCreateSessionOptions), uintptr(unsafe.Pointer(&so)))
	if err := l.status(st, "CreateSessionOptions"); err != nil {
		return 0, err
	}

	st, _, _ = purego.SyscallN(l.fn(idxSetSessionGraphOptimizationLevel), so, graphOptAll)
	if err := l.status(st, "SetSessionGraphOptimizationLevel"); err != nil {
		purego.SyscallN(l.fn(idxReleaseSessionOptions), so)
		return 0, err
	}
	if opts.IntraOpThreads > 0 {
		st, _, _ = purego.SyscallN(l.fn(idxSetIntraOpNumThreads), so, uintptr(opts.IntraOpThreads))
		if err := l.status(st, "SetIntraOpNumThreads"); err != nil {
			purego.SyscallN(l.fn(idxReleaseSessionOptions), so)
			return 0, err
		}
	}
	return so, nil
}

// Close releases the session.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	purego.SyscallN(s.lib.fn(idxReleaseSession), s.sess)
	purego.SyscallN(s.lib.fn(idxReleaseSessionOptions), s.opts)
	s.closed = true
}

// InputNames returns the model's input names, in order.
func (s *Session) InputNames() ([]string, error) {
	return s.names(idxSessionGetInputCount, idxSessionGetInputName, "input")
}

// OutputNames returns the model's output names, in order.
func (s *Session) OutputNames() ([]string, error) {
	return s.names(idxSessionGetOutputCount, idxSessionGetOutputName, "output")
}

func (s *Session) names(countIdx, nameIdx int, what string) ([]string, error) {
	var alloc uintptr
	st, _, _ := purego.SyscallN(s.lib.fn(idxGetAllocatorWithDefaultOptions), uintptr(unsafe.Pointer(&alloc)))
	if err := s.lib.status(st, "GetAllocatorWithDefaultOptions"); err != nil {
		return nil, err
	}

	var n uintptr
	st, _, _ = purego.SyscallN(s.lib.fn(countIdx), s.sess, uintptr(unsafe.Pointer(&n)))
	if err := s.lib.status(st, "SessionGet"+what+"Count"); err != nil {
		return nil, err
	}

	out := make([]string, 0, n)
	for i := uintptr(0); i < n; i++ {
		var namePtr uintptr
		st, _, _ = purego.SyscallN(s.lib.fn(nameIdx), s.sess, i, alloc, uintptr(unsafe.Pointer(&namePtr)))
		if err := s.lib.status(st, "SessionGet"+what+"Name"); err != nil {
			return nil, err
		}
		out = append(out, goString(namePtr))
		// The allocator owns the string; not freeing it leaks once per name
		// per call, which adds up across a long-lived daemon.
		purego.SyscallN(s.lib.fn(idxAllocatorFree), alloc, namePtr)
	}
	return out, nil
}

// Tensor is a dense tensor. Exactly one of Floats and Int64s is populated.
type Tensor struct {
	Shape  []int64
	Floats []float32
	Int64s []int64
}

// NewFloatTensor builds a float32 tensor.
func NewFloatTensor(shape []int64, data []float32) *Tensor {
	return &Tensor{Shape: shape, Floats: data}
}

// NewInt64Tensor builds an int64 tensor, which is what token IDs are.
func NewInt64Tensor(shape []int64, data []int64) *Tensor {
	return &Tensor{Shape: shape, Int64s: data}
}

func (t *Tensor) elemCount() int64 {
	n := int64(1)
	for _, d := range t.Shape {
		n *= d
	}
	return n
}

// Run executes the model.
//
// Every OrtValue created here is released before returning, including on the
// error paths, because a failed inference is exactly when a daemon is most
// likely to retry and least able to afford a leak per attempt.
func (s *Session) Run(inputs map[string]*Tensor, outputNames []string) ([]*Tensor, error) {
	if len(inputs) == 0 {
		return nil, errors.New("onnxrt: no inputs")
	}
	if len(outputNames) == 0 {
		return nil, errors.New("onnxrt: no output names")
	}

	var memInfo uintptr
	st, _, _ := purego.SyscallN(s.lib.fn(idxCreateCpuMemoryInfo), 0 /*OrtDeviceAllocator*/, 0 /*OrtMemTypeDefault*/, uintptr(unsafe.Pointer(&memInfo)))
	if err := s.lib.status(st, "CreateCpuMemoryInfo"); err != nil {
		return nil, err
	}
	defer purego.SyscallN(s.lib.fn(idxReleaseMemoryInfo), memInfo)

	var (
		inNameBufs [][]byte
		inNamePtrs []uintptr
		inValues   []uintptr
		keepAlive  []any
	)
	release := func() {
		for _, v := range inValues {
			if v != 0 {
				purego.SyscallN(s.lib.fn(idxReleaseValue), v)
			}
		}
	}

	for name, t := range inputs {
		v, ka, err := s.newValue(memInfo, t)
		if err != nil {
			release()
			return nil, fmt.Errorf("input %q: %w", name, err)
		}
		nb := cstring(name)
		inNameBufs = append(inNameBufs, nb)
		inNamePtrs = append(inNamePtrs, uintptr(unsafe.Pointer(&nb[0])))
		inValues = append(inValues, v)
		keepAlive = append(keepAlive, ka)
	}
	defer release()

	outNameBufs := make([][]byte, 0, len(outputNames))
	outNamePtrs := make([]uintptr, 0, len(outputNames))
	for _, name := range outputNames {
		nb := cstring(name)
		outNameBufs = append(outNameBufs, nb)
		outNamePtrs = append(outNamePtrs, uintptr(unsafe.Pointer(&nb[0])))
	}
	outValues := make([]uintptr, len(outputNames))

	st, _, _ = purego.SyscallN(s.lib.fn(idxRun), s.sess, 0,
		uintptr(unsafe.Pointer(&inNamePtrs[0])), uintptr(unsafe.Pointer(&inValues[0])), uintptr(len(inValues)),
		uintptr(unsafe.Pointer(&outNamePtrs[0])), uintptr(len(outNamePtrs)),
		uintptr(unsafe.Pointer(&outValues[0])))

	// ONNX Runtime reads the tensor data buffers for the whole call, so the
	// Go slices behind them must not be collected until Run returns.
	runtime.KeepAlive(keepAlive)
	runtime.KeepAlive(inNameBufs)
	runtime.KeepAlive(outNameBufs)

	if err := s.lib.status(st, "Run"); err != nil {
		for _, v := range outValues {
			if v != 0 {
				purego.SyscallN(s.lib.fn(idxReleaseValue), v)
			}
		}
		return nil, err
	}

	defer func() {
		for _, v := range outValues {
			if v != 0 {
				purego.SyscallN(s.lib.fn(idxReleaseValue), v)
			}
		}
	}()

	results := make([]*Tensor, 0, len(outValues))
	for i, v := range outValues {
		t, err := s.readValue(v)
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", outputNames[i], err)
		}
		results = append(results, t)
	}
	return results, nil
}

// newValue wraps a Go-backed tensor as an OrtValue. The returned value must
// be released by the caller; the returned keep-alive must outlive the run.
func (s *Session) newValue(memInfo uintptr, t *Tensor) (uintptr, any, error) {
	if t == nil || len(t.Shape) == 0 {
		return 0, nil, errors.New("tensor has no shape")
	}
	want := t.elemCount()

	var (
		dataPtr  unsafe.Pointer
		dataLen  uintptr
		elemType uintptr
		ka       any
	)
	switch {
	case t.Floats != nil && t.Int64s != nil:
		return 0, nil, errors.New("tensor has both float and int64 data")
	case t.Floats != nil:
		if int64(len(t.Floats)) != want {
			return 0, nil, fmt.Errorf("shape %v needs %d values, got %d", t.Shape, want, len(t.Floats))
		}
		dataPtr = unsafe.Pointer(&t.Floats[0])
		dataLen = uintptr(len(t.Floats)) * 4
		elemType = tensorFloat
		ka = t.Floats
	case t.Int64s != nil:
		if int64(len(t.Int64s)) != want {
			return 0, nil, fmt.Errorf("shape %v needs %d values, got %d", t.Shape, want, len(t.Int64s))
		}
		dataPtr = unsafe.Pointer(&t.Int64s[0])
		dataLen = uintptr(len(t.Int64s)) * 8
		elemType = tensorInt64
		ka = t.Int64s
	default:
		return 0, nil, errors.New("tensor has no data")
	}

	shape := t.Shape
	var v uintptr
	st, _, _ := purego.SyscallN(s.lib.fn(idxCreateTensorWithDataAsOrtValue), memInfo,
		uintptr(dataPtr), dataLen,
		uintptr(unsafe.Pointer(&shape[0])), uintptr(len(shape)),
		elemType, uintptr(unsafe.Pointer(&v)))
	runtime.KeepAlive(shape)
	if err := s.lib.status(st, "CreateTensorWithDataAsOrtValue"); err != nil {
		return 0, nil, err
	}
	return v, ka, nil
}

// readValue copies an output tensor into Go memory.
//
// It copies rather than aliasing: the buffer belongs to the OrtValue, which
// is released as soon as Run returns, so a slice pointing into it would be a
// use-after-free that reads plausible numbers.
func (s *Session) readValue(v uintptr) (*Tensor, error) {
	if v == 0 {
		return nil, errors.New("null output value")
	}

	var info uintptr
	st, _, _ := purego.SyscallN(s.lib.fn(idxGetTensorTypeAndShape), v, uintptr(unsafe.Pointer(&info)))
	if err := s.lib.status(st, "GetTensorTypeAndShape"); err != nil {
		return nil, err
	}
	defer purego.SyscallN(s.lib.fn(idxReleaseTensorTypeAndShapeInfo), info)

	var ndim uintptr
	st, _, _ = purego.SyscallN(s.lib.fn(idxGetDimensionsCount), info, uintptr(unsafe.Pointer(&ndim)))
	if err := s.lib.status(st, "GetDimensionsCount"); err != nil {
		return nil, err
	}
	shape := make([]int64, ndim)
	if ndim > 0 {
		st, _, _ = purego.SyscallN(s.lib.fn(idxGetDimensions), info, uintptr(unsafe.Pointer(&shape[0])), ndim)
		if err := s.lib.status(st, "GetDimensions"); err != nil {
			return nil, err
		}
	}

	var data uintptr
	st, _, _ = purego.SyscallN(s.lib.fn(idxGetTensorMutableData), v, uintptr(unsafe.Pointer(&data)))
	if err := s.lib.status(st, "GetTensorMutableData"); err != nil {
		return nil, err
	}

	t := &Tensor{Shape: shape}
	n := t.elemCount()
	if n < 0 {
		return nil, fmt.Errorf("output has a negative element count for shape %v", shape)
	}
	t.Floats = make([]float32, n)
	copy(t.Floats, unsafe.Slice((*float32)(fromC(data)), n))
	return t, nil
}

// cstring returns a NUL-terminated copy for passing to C.
func cstring(s string) []byte { return append([]byte(s), 0) }

// goString copies a NUL-terminated C string into Go memory.
func goString(p uintptr) string {
	if p == 0 {
		return ""
	}
	base := fromC(p)
	n := 0
	for *(*byte)(unsafe.Add(base, n)) != 0 {
		n++
	}
	return string(unsafe.Slice((*byte)(base), n))
}

// fromC converts a pointer returned by ONNX Runtime into an unsafe.Pointer.
//
// go vet's unsafeptr check flags this, and the flag is not a false positive
// in general: converting a uintptr to a pointer is unsound when the uintptr
// holds a GO address, because the garbage collector neither sees it nor keeps
// the object alive. Every value passed here is a C address from
// purego.SyscallN -- memory ONNX Runtime allocated, which Go's collector does
// not manage and cannot move -- so the hazard the check exists for does not
// apply.
//
// It is written directly rather than through a bit-reinterpreting helper that
// vet cannot see through. That would silence the tool while performing the
// identical operation, which is worse than leaving the warning visible: the
// next reader would have no signal that anything unusual happens here.
//
// The conversion is irreducible for a cgo-free binding. purego's calling
// convention is uintptr-in, uintptr-out, so a C pointer can only arrive as an
// integer. Isolating it in one function keeps the unsafety auditable, and
// nothing else in this package converts an integer to a pointer.
func fromC(p uintptr) unsafe.Pointer {
	return unsafe.Pointer(p) //nolint:govet // C address, not Go memory; see doc comment
}

// toC converts back for passing to purego.
func toC(p unsafe.Pointer) uintptr { return uintptr(p) }
