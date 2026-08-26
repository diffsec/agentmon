//go:build !darwin

package api

import (
	"net/http"

	"github.com/diffsec/agentmon/pkg/types"
)

// platformWrapInit is the non-darwin stub. Linux reaches its own seccomp and
// ptrace paths further down wrapInitCore and never calls this.
func platformWrapInit(_ *App, _ string, _ types.WrapInitRequest) (types.WrapInitResponse, int, error) {
	return types.WrapInitResponse{}, http.StatusBadRequest, errWrapNotSupported
}
