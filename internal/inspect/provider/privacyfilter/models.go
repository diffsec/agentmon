package privacyfilter

import (
	"fmt"

	"github.com/diffsec/agentmon/internal/inspect/provider/privacyfilter/modelcache"
)

// Revision pins the openai/privacy-filter commit every URL below resolves
// against.
//
// A branch name would move under us: the same URL would return different
// weights after an upstream push, the digests would stop matching, and every
// agentmon install would start failing at once with no local change to explain
// it. Pinning means an upstream update is something we adopt deliberately.
const Revision = "7ffa9a043d54d1be65afb281eddf0ffbe629385b"

// hfURL builds a download URL for a file at the pinned revision.
func hfURL(path string) string {
	return "https://huggingface.co/openai/privacy-filter/resolve/" + Revision + "/" + path
}

// Variant selects which quantisation of the model to run. They differ in size
// and in accuracy; the graph and the label taxonomy are identical.
type Variant string

const (
	// VariantQ4 is 4-bit quantised: 917MB, the default.
	VariantQ4 Variant = "q4"
	// VariantQ4F16 is 4-bit with fp16 activations: 809MB, slightly smaller.
	VariantQ4F16 Variant = "q4f16"
)

// SpecFor returns the download spec for a variant.
//
// Digests are the SHA-256 of the file contents at Revision, computed by
// scripts/model-digests.sh rather than typed by hand. They are what make the
// download source irrelevant: Hugging Face today, a release mirror if that is
// ever blocked, or an operator populating the directory by other means -- the
// bytes either match or they are refused.
func SpecFor(v Variant) (modelcache.Spec, error) {
	// Files shared by every variant. tokenizer.json is the largest of them
	// at 27MB and is the same for all.
	common := []modelcache.File{
		{
			Name: "tokenizer.json", URL: hfURL("tokenizer.json"),
			Size: 27868174, SHA256: "0614fe83cadab421296e664e1f48f4261fa8fef6e03e63bb75c20f38e37d07d3",
		},
		{
			Name: "config.json", URL: hfURL("config.json"),
			Size: 3039, SHA256: "b2b26a4a4a000639ad30b0c264adbefe365bdb567fbd7bb27303b8c438375bd1",
		},
		{
			Name: "viterbi_calibration.json", URL: hfURL("viterbi_calibration.json"),
			Size: 372, SHA256: "bbc8611ef08a55ed72d64856cbbbb9a91db8dfa881f0a92e2afbad6e4bbc775a",
		},
	}

	switch v {
	case VariantQ4:
		// The graph and its weights must land side by side under exactly
		// these names: model_q4.onnx references model_q4.onnx_data by
		// relative path, and ONNX Runtime resolves it against the graph's
		// own directory.
		return modelcache.Spec{
			Name: "privacy-filter-q4",
			Files: append(common,
				modelcache.File{
					Name: "model_q4.onnx", URL: hfURL("onnx/model_q4.onnx"),
					Size: 160219, SHA256: "8f7dee8b46d096f052b359375dfba5d983cc4d18c44a783bf548615c472f8dea",
				},
				modelcache.File{
					Name: "model_q4.onnx_data", URL: hfURL("onnx/model_q4.onnx_data"),
					Size: 917120144, SHA256: "f30998e28c71c5374cc7e8b7de8f0f83e981592c0c2d652d2ad4928454dbb496",
				},
			),
		}, nil

	default:
		return modelcache.Spec{}, fmt.Errorf("privacyfilter: unknown model variant %q (known: %s)", v, VariantQ4)
	}
}

// GraphFile returns the .onnx file within a variant's cache directory.
func GraphFile(v Variant) (string, error) {
	switch v {
	case VariantQ4:
		return "model_q4.onnx", nil
	default:
		return "", fmt.Errorf("privacyfilter: unknown model variant %q", v)
	}
}
